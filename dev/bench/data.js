window.BENCHMARK_DATA = {
  "lastUpdate": 1791644864368,
  "repoUrl": "https://github.com/BitspendPayment/enclave-runtime",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b8254f69cde2f96646ae20d364e195d20672ac0f",
          "message": "Merge pull request #1 from BitspendPayment/merkle-block-store\n\nNew Runtime (Yippy Hurra)",
          "timestamp": "2026-09-26T09:21:32+03:00",
          "tree_id": "20dfc264bbc2618301549bcaaf213c6050c44a02",
          "url": "https://github.com/BitspendPayment/enclave-runtime/commit/b8254f69cde2f96646ae20d364e195d20672ac0f"
        },
        "date": 1790404528763,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 25825,
            "range": "± 3807",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 139946,
            "range": "± 9382",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 769513,
            "range": "± 25547",
            "unit": "ns/iter"
          },
          {
            "name": "guest/mount",
            "value": 52638,
            "range": "± 1541",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/1024",
            "value": 414193,
            "range": "± 19436",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/65536",
            "value": 487052,
            "range": "± 24167",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/1048576",
            "value": 1578441,
            "range": "± 177612",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/1",
            "value": 83476,
            "range": "± 3381",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/16",
            "value": 151169,
            "range": "± 5929",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/256",
            "value": 1301640,
            "range": "± 47827",
            "unit": "ns/iter"
          },
          {
            "name": "random_read/4096",
            "value": 2868,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "random_read/65536",
            "value": 5190,
            "range": "± 155",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/10",
            "value": 1857,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/1000",
            "value": 7011,
            "range": "± 247",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/10000",
            "value": 13009,
            "range": "± 313",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c2ea60ea573ba294cd9a807a9bf3b174d78e7378",
          "message": "Merge pull request #3 from BitspendPayment/nitro-deployment\n\nZFS storage: per-tenant pools and the rollback-integrity fix",
          "timestamp": "2026-10-10T17:59:16+03:00",
          "tree_id": "275e6ad5dbc3e849ec250ed7ef3b85f2f6135002",
          "url": "https://github.com/BitspendPayment/enclave-runtime/commit/c2ea60ea573ba294cd9a807a9bf3b174d78e7378"
        },
        "date": 1791644863781,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 34886,
            "range": "± 2408",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 125501,
            "range": "± 7063",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 834533,
            "range": "± 1164455",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}