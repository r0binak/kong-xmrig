# kong-xmrig
[![Docker Pulls](https://badgen.net/docker/pulls/r0binak/kong-xmrig?icon=docker&label=pulls)](https://hub.docker.com/r/r0binak/kong-xmrig/)

Reproducing a vulnerable version docker image of Kong Ingress Controller 3.4.0 with XMRig cryptominer.
> :warning: **For educational purposes only**: The image, or rather the `manager` executable file from the vulnerable image contains the XMRig miner. Never run it in a production environment.

## Dockerfile
This is taken from a build of the [original](https://github.com/Kong/kubernetes-ingress-controller/blob/main/Dockerfile#L93-L111) Kong Ingress Controller image.

```dockerfile
FROM gcr.io/distroless/static:nonroot@sha256:6ec5aa99dc335666e79dc64e4a6c8b89c33a543a1967f20d360922a80dd21f02

WORKDIR /
COPY manager .
USER 1000:1000

ENTRYPOINT ["/manager"]
```

## YARA rule's
```yara
rule u42_crime_win_kongtrojan
{
    meta:
        author = "Kong"
        date = "2025-01-09"
        description = "Detects the trojanized Kong manager binary."
        hash = "e164e6e21c661679c556d16638300c25e16d86bb2d567ad66b4181f1a65f4788"

    strings:
        $golang = "golang.org"
        $v1 = "Kong does not care about security"
        $v2 = "KongIngress"
        $v3 = "f0VMR"  // start of b64 XMrig
    condition:
        $golang and (all of ($v*))
}

rule u42_win_hacktool_XMRig_Miner: XMRig windows_memory
{
  meta:
    author = "Kong"
    date = "2024-08-23"
    description = "XMRig Miner"
    hash = "56ff46874f0536c289ff38af4cb308af8f7e6156e3f9d9227b71004d2042a4e6"

  strings:
    $s01 = "XMRig"
        $s02 = "nicehash.com"
    $s03 = "tls-fingerprint"
        $s04 = "stratum+tcp://"
    $s05 = "stratum+ssl://"
        $s06 = "cryptonight" fullword
    $s07 = "cryptonightv7" fullword
        $s08 = "cryptonightheavy" fullword
    $s09 = "cryptonightv8" fullword
        $s10 = ".minergate.com"
    $s11 = "xmr.pool" fullword
        $s12 = "aeon.pool"
    $s13 = "worker-id"
        $s14 = "no active pools, stop mining"
    $s15 = "CryptonightR"
    $s16 = "<UV_THREADPOOL_SIZE"
    $s17 = "src/threadpool.c"
        $s18 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
    $s19 = "paused, press 'r' to resume"
        $s20 = "Ctrl+C received, exiting"
    $s21 = "Usage: xmrig [OPTIONS]"
        $s22 = "rig-id"
    $s23 = "\"%s\" was changed, reloading configuration"
        $s24 = "Unknown/unsupported algorithm detected, reconnect"
    $s25 = "speed 10s/60s/15m"
    $cmd01 = "specify the algorithm to use"
        $cmd02 = "URL of mining server"
    $cmd03 = "username:password pair for mining server"
        $cmd04 = "username for mining server"
    $cmd05 = "password for mining server"
        $cmd06 = "rig identifier for pool-side statistics (needs pool support)"
    $cmd07 = "number of miner threads"
        $cmd08 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1"
    $cmd09 = "set process priority (0 idle, 2 normal to 5 highest)"
        $cmd10 = "algorithm PoW variant"
    $cmd11 = "donate level, default 5%% (5 minutes in 100 minutes)"
        $cmd12 = "set custom user-agent string for pool"
    $cmd13 = "print hashrate report every N seconds"
        $cmd14 = "port for the miner API"
    $fmt01 = "%-13s%s/%s %s"
        $fmt02 = "%-13slibuv/%s %s"
    $fmt03 = "%-13s%s (%d) %sx64 %sAES %sAVX2"
        $fmt04 = "%-13s%.1f MB/%.1f MB"
    $fmt05 = "%-13s%d, %s, av=%d, %sdonate=%d%%%s"
        $fmt06 = "%-13sauto:%s"
    $fmt07 = "POOL #%-7zu%s%s variant=%s %s"
        $fmt08 = "{\"id\":%lld,\"jsonrpc\":\"2.0\",\"method\":\"keepalived\",\"params\":{\"id\":\"%s\"}}"
    $fmt09 = "[%s] duplicate job received, reconnect"
        $fmt10 = "%s| THREAD | AFFINITY | 10s H/s | 60s H/s | 15m H/s |"
    $fmt11 = "READY (CPU) threads %zu(%zu) huge pages %zu/%zu %1.0f%% memory %zu KB"
        $fmt12 = "use pool %s:%d %s %s"
    $fmt13 = "rejected (%lld/%lld) diff %u \"%s\" (%llu ms)"
        $fmt14 = "accepted (%lld/%lld) diff %u (%llu ms)"
    $fmt15 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
  condition:
    (
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        or (uint32(0) == 0x464C457F)
    )
    and 5 of ($s*)
        and (
            5 of ($cmd*)
        or 5 of ($fmt*)
    )
} 
```

## References
- [Blog Post](https://konghq.com/blog/product-releases/december-2024-unauthorized-kong-ingress-controller-3-4-0-build)
- [GitHub advisory](https://github.com/Kong/kubernetes-ingress-controller/security/advisories/GHSA-58mg-ww7q-xw3p)
- [Detection YARA Rules](https://github.com/Yara-Rules/rules/pull/448/files)
