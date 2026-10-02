"""Resume tests: crash (kill -9) of the receiver, manual pause/resume on both sides, directory, cancel.
Usage: resume.py <path-to-lanshared>"""
import asyncio, os, shutil, signal, sys, tempfile, time
from common import Ctl, sha, spawn_two, start, pair

BIN = sys.argv[1]
MB = 1 << 20


async def until_progress(c, tid, nbytes, timeout=60):
    end = time.time() + timeout
    while True:
        m = await c.wait("progress", max(0.1, end - time.time()), xfer=tid)
        if m["bytes"] >= nbytes:
            return m


async def until_state(c, tid, state, timeout=60):
    end = time.time() + timeout
    while True:
        m = await c.wait("xfer_state", max(0.1, end - time.time()), xfer=tid)
        if m["state"] == state:
            return m


async def offer(a, b, bid, src, dest):
    tid = (await a.call("send", peer=bid, paths=[src]))["xfers"][0]
    inc = await b.wait("incoming")
    assert inc["xfer"] == tid
    await b.call("accept", xfer=tid, dest=dest)
    await until_state(b, tid, "running")
    return tid


def mkfile(p, mb):
    with open(p, "wb") as f:
        for _ in range(mb):
            f.write(os.urandom(MB))


async def reopen(cfg):
    c = Ctl(cfg)
    await c.open()
    return c


async def main():
    tmp = tempfile.mkdtemp()
    cfgs, procs = spawn_two(BIN, tmp, {"LANSHARE_THROTTLE": str(60 * MB)})
    try:
        a, b = await reopen(cfgs[0]), await reopen(cfgs[1])
        aid, bid = await pair(a, b)
        src = os.path.join(tmp, "src"); os.makedirs(src)
        out = os.path.join(tmp, "out"); os.makedirs(out)
        big = os.path.join(src, "big.bin"); mkfile(big, 150)

        # 1. receiver crashes (kill -9) mid-file and comes back: automatic resume, no new prompt
        dest = os.path.join(out, "big1.bin")
        tid = await offer(a, b, bid, big, dest)
        await until_progress(b, tid, 40 * MB)
        procs[1].send_signal(signal.SIGKILL); procs[1].wait()
        partial = os.path.getsize(dest)
        assert 0 < partial < 150 * MB, partial
        await until_state(a, tid, "retrying")
        procs[1] = start(BIN, cfgs, 1)
        b = await reopen(cfgs[1])
        st = await b.call("state")
        assert [t["state"] for t in st["transfers"]] == ["interrupted"], st["transfers"]
        run = await until_state(b, tid, "running", 60)
        assert run["resumed"] and run["offset"] >= partial - MB, run
        d = await b.wait("done", 60, xfer=tid)
        assert d["ok"] and (await a.wait("done", 60, xfer=tid))["ok"]
        assert sha(dest) == sha(big)
        print(f"1. kill -9 receiver, auto-resume from {run['offset'] // MB} MiB: ok")

        # 2. manual pause / resume on the sender
        dest = os.path.join(out, "big2.bin")
        tid = await offer(a, b, bid, big, dest)
        await until_progress(b, tid, 30 * MB)
        await a.call("pause", xfer=tid)
        await until_state(a, tid, "paused")
        await asyncio.sleep(0.5)
        got = os.path.getsize(dest)
        await asyncio.sleep(1.0)
        assert os.path.getsize(dest) == got < 150 * MB, "data still flowing while paused"
        await a.call("resume", xfer=tid)
        run = await until_state(b, tid, "running", 30)
        assert run["resumed"] and run["offset"] > 0
        assert (await b.wait("done", 60, xfer=tid))["ok"]
        assert sha(dest) == sha(big)
        print(f"2. sender pause/resume at {got // MB} MiB: ok")

        # 3. pause on the receiver side, then resume there
        dest = os.path.join(out, "big3.bin")
        tid = await offer(a, b, bid, big, dest)
        await until_progress(b, tid, 30 * MB)
        await b.call("pause", xfer=tid)
        await until_state(b, tid, "paused")
        r = await until_state(a, tid, "retrying")
        await asyncio.sleep(1.5)
        await b.call("resume", xfer=tid)
        assert (await b.wait("done", 60, xfer=tid))["ok"]
        assert sha(dest) == sha(big)
        print("3. receiver pause/resume: ok")

        # 4. directory, crash mid-way: finished files are skipped, current one continues at its offset
        tree = os.path.join(src, "tree"); os.makedirs(os.path.join(tree, "sub"))
        for i in range(5):
            mkfile(os.path.join(tree, "sub" if i % 2 else "", f"f{i}.bin"), 30)
        open(os.path.join(tree, "empty.txt"), "w").close()
        os.makedirs(os.path.join(tree, "emptydir"))
        os.makedirs(os.path.join(out, "d"))
        tid = await offer(a, b, bid, tree, os.path.join(out, "d"))
        await until_progress(b, tid, 70 * MB)
        procs[1].send_signal(signal.SIGKILL); procs[1].wait()
        procs[1] = start(BIN, cfgs, 1)
        b = await reopen(cfgs[1])
        run = await until_state(b, tid, "running", 60)
        assert run["resumed"], run
        assert (await b.wait("done", 90, xfer=tid))["ok"]
        for i in range(5):
            rel = os.path.join("sub" if i % 2 else "", f"f{i}.bin")
            assert sha(os.path.join(out, "d", "tree", rel)) == sha(os.path.join(tree, rel)), rel
        assert os.path.isdir(os.path.join(out, "d", "tree", "emptydir"))
        print("4. directory crash-resume: ok")

        # 5. receiver cancels: sender gives up for good, partial file removed
        dest = os.path.join(out, "big5.bin")
        tid = await offer(a, b, bid, big, dest)
        await until_progress(b, tid, 20 * MB)
        await b.call("cancel", xfer=tid)
        d = await a.wait("done", 30, xfer=tid)
        assert not d["ok"] and "cancel" in d["error"], d
        assert not os.path.exists(dest)
        print("5. receiver cancel:", d["error"])

        # 6. sender cancels while paused-by-error: record disappears
        tid = await offer(a, b, bid, big, os.path.join(out, "big6.bin"))
        await until_progress(b, tid, 10 * MB)
        await a.call("cancel", xfer=tid)
        assert not (await a.wait("done", 30, xfer=tid))["ok"]
        assert not (await a.call("state"))["transfers"]
        print("6. sender cancel: ok")
        print("ALL RESUME TESTS OK")
    finally:
        for p in procs:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)

asyncio.run(main())
