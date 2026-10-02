import asyncio, hashlib, json, os, subprocess, tempfile, time


class Ctl:
    def __init__(self, cfg):
        rt = json.load(open(os.path.join(cfg, "runtime.json")))
        self.rt, self.n, self.fut, self.events = rt, 0, {}, asyncio.Queue()

    async def open(self):
        self.r, self.w = await asyncio.open_connection("127.0.0.1", self.rt["port"])
        self.task = asyncio.create_task(self.loop())
        await self.call("auth", token=self.rt["token"])

    async def loop(self):
        async for line in self.r:
            m = json.loads(line)
            if "re" in m:
                self.fut.pop(m["re"]).set_result(m)
            else:
                self.events.put_nowait(m)

    async def call(self, cmd, **kw):
        self.n += 1
        f = self.fut[self.n] = asyncio.get_running_loop().create_future()
        self.w.write((json.dumps({"cmd": cmd, "rid": self.n, **kw}) + "\n").encode())
        m = await asyncio.wait_for(f, 60)
        assert m["ok"], m
        return m.get("data")

    async def wait(self, ev, timeout=30, **match):
        end = time.time() + timeout
        while True:
            m = await asyncio.wait_for(self.events.get(), max(0.1, end - time.time()))
            if m["event"] == ev and all(m.get(k) == v for k, v in match.items()):
                return m


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def spawn_two(binary, tmp, env_a=None):
    """Start daemons A and B on loopback; returns (cfgs, procs)."""
    cfgs = [os.path.join(tmp, "A"), os.path.join(tmp, "B")]
    procs = [start(binary, cfgs, i, env_a if i == 0 else None) for i in range(2)]
    return cfgs, procs


def start(binary, cfgs, i, env=None):
    o = 1 - i
    for _ in range(1):
        pass
    try:
        os.remove(os.path.join(cfgs[i], "runtime.json"))
    except OSError:
        pass
    p = subprocess.Popen([binary, "--config-dir", cfgs[i], "--tcp-port", str(47701 + i), "--udp-port", str(47711 + i),
                          "--extra-bcast", f"127.0.0.1:{47711 + o}", "--name", "AB"[i]], env={**os.environ, **(env or {})})
    for _ in range(100):
        if os.path.exists(os.path.join(cfgs[i], "runtime.json")):
            break
        time.sleep(0.05)
    return p


async def pair(a, b):
    sa, sb = await a.call("state"), await b.call("state")
    aid, bid = sa["identity"]["id"], sb["identity"]["id"]
    await b.call("set_settings", broadcast=True)
    await a.call("search")
    await b.wait("pair_proposal")
    await asyncio.sleep(0.5)
    await a.call("pair_add", id=bid)
    await b.wait("pair_request")
    await b.call("pair_add", id=aid)
    await a.wait("paired", 10)
    return aid, bid
