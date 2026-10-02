"""End-to-end test: two daemons on loopback. Usage: e2e.py <path-to-lanshared> [big_mb]"""
import asyncio, os, shutil, subprocess, sys, tempfile, time
from common import Ctl, sha

BIN = sys.argv[1]
BIG = int(sys.argv[2]) if len(sys.argv) > 2 else 64


async def transfer(a, b, bid, src, dest):
    t = time.time()
    r = await a.call("send", peer=bid, paths=[src])
    x = r["xfers"][0]
    inc = await b.wait("incoming")
    await b.call("accept", xfer=inc["xfer"], dest=dest)
    d = await b.wait("done", 120, xfer=inc["xfer"])
    ad = await a.wait("done", 120, xfer=x)
    assert d["ok"] and ad["ok"], (d, ad)
    return inc, time.time() - t


async def main():
    tmp = tempfile.mkdtemp()
    cfgs = [os.path.join(tmp, "A"), os.path.join(tmp, "B")]
    procs = []
    for i, c in enumerate(cfgs):
        o = 1 - i
        procs.append(subprocess.Popen([BIN, "--config-dir", c, "--tcp-port", str(47701 + i), "--udp-port", str(47711 + i),
                                       "--extra-bcast", f"127.0.0.1:{47711 + o}", "--name", "AB"[i]]))
    try:
        for _ in range(50):
            if all(os.path.exists(os.path.join(c, "runtime.json")) for c in cfgs):
                break
            time.sleep(0.1)
        a, b = Ctl(cfgs[0]), Ctl(cfgs[1])
        await a.open(); await b.open()
        sa, sb = await a.call("state"), await b.call("state")
        aid, bid = sa["identity"]["id"], sb["identity"]["id"]

        await b.call("set_settings", broadcast=True)
        await a.call("search")
        prop = await b.wait("pair_proposal")
        assert prop["info"]["id"] == aid
        print("B was proposed A: ok")
        await a.wait("discovered", 10) if False else None
        await asyncio.sleep(0.5)
        st = await a.call("state")
        assert any(d["info"]["id"] == bid for d in st["discovered"]), st["discovered"]
        print("A discovered B: ok", st["discovered"])

        assert (await a.call("pair_add", id=bid))["status"] == "pending"
        req = await b.wait("pair_request")
        assert req["info"]["id"] == aid
        assert (await b.call("pair_add", id=aid))["status"] == "accepted"
        await a.wait("paired", 10)
        print("mutual pairing: ok")

        src = os.path.join(tmp, "src"); os.makedirs(os.path.join(src, "sub"))
        big = os.path.join(src, "big.bin")
        with open(big, "wb") as f:
            for _ in range(BIG):
                f.write(os.urandom(1 << 20))
        open(os.path.join(src, "sub", "x.txt"), "w").write("hello")
        out = os.path.join(tmp, "out"); os.makedirs(out)

        for enc in (False, True):
            await a.call("set_settings", require_encryption=enc)
            await b.call("set_settings", require_encryption=False)
            dest = os.path.join(out, f"big_{enc}.bin")
            inc, dt = await transfer(a, b, bid, big, dest)
            assert inc["encrypted"] == enc
            assert sha(dest) == sha(big)
            print(f"file enc={enc}: {BIG / dt:.0f} MiB/s ok")
        # receiver-side requirement forces encryption
        await a.call("set_settings", require_encryption=False)
        await b.call("set_settings", require_encryption=True)
        inc, _ = await transfer(a, b, bid, os.path.join(src, "sub", "x.txt"), os.path.join(out, "x.txt"))
        assert inc["encrypted"] is True
        print("receiver-forced encryption: ok")
        await b.call("set_settings", require_encryption=False)

        os.makedirs(os.path.join(out, "d"))
        inc, dt = await transfer(a, b, bid, src, os.path.join(out, "d"))
        assert sha(os.path.join(out, "d", "src", "big.bin")) == sha(big)
        assert open(os.path.join(out, "d", "src", "sub", "x.txt")).read() == "hello"
        print(f"directory: {BIG / dt:.0f} MiB/s ok")

        # many small files + sizes around the batching threshold (128 KiB), nested dirs, empty dir
        many = os.path.join(src, "many")
        for i in range(3000):
            d = os.path.join(many, f"d{i % 30}")
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, f"f{i}.txt"), "wb").write(os.urandom(i % 3000))
        for n in (0, 1, 131071, 131072, 131073, 1 << 20):
            open(os.path.join(many, f"edge_{n}.bin"), "wb").write(os.urandom(n))
        os.makedirs(os.path.join(many, "emptydir"))
        os.makedirs(os.path.join(out, "m"))
        for enc in (False, True):
            await a.call("set_settings", require_encryption=enc)
            t0 = time.time()
            dest = os.path.join(out, "m", str(enc)); os.makedirs(dest)
            await transfer(a, b, bid, many, dest)
            dt = time.time() - t0
            for root, dirs, files in os.walk(many):
                for f in files:
                    q = os.path.join(root, f)
                    r = os.path.join(dest, "many", os.path.relpath(q, many))
                    assert os.path.getsize(r) == os.path.getsize(q) and sha(r) == sha(q), r
            assert os.path.isdir(os.path.join(dest, "many", "emptydir"))
            print(f"3006 small files enc={enc}: {3006 / dt:.0f} files/s ok")
        await a.call("set_settings", require_encryption=False)

        # block
        await b.call("peer_block", id=aid, blocked=True)
        r = await a.call("send", peer=bid, paths=[big])
        d = await a.wait("done", 20, xfer=r["xfers"][0])
        assert not d["ok"]
        print("blocked peer rejected:", d["error"])
        # reject
        await b.call("peer_block", id=aid, blocked=False)
        r = await a.call("send", peer=bid, paths=[big])
        inc = await b.wait("incoming")
        await b.call("reject", xfer=inc["xfer"])
        d = await a.wait("done", 20, xfer=r["xfers"][0])
        assert not d["ok"]
        print("declined transfer: ok")
        print("ALL OK")
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(tmp, ignore_errors=True)

asyncio.run(main())
