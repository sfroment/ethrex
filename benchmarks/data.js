window.BENCHMARK_DATA = {
  "lastUpdate": 1757516720242,
  "repoUrl": "https://github.com/sfroment/ethrex",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "mrugiero@gmail.com",
            "name": "Mario Rugiero",
            "username": "Oppen"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3565e63abdfeb7fdbb7bfd6b40943b0c891cc6eb",
          "message": "fix(l1): make account and storage ranges handlers async (#4401)\n\n**Motivation**\n\nThese handlers are currently sync and can block the runtime for quite a\nlong time. This is not the ideal solution for this; we still need to do\nthings better so the handler itself doesn't take a long time to fetch\nthe requested nodes. We'll tackle this on a subsequent PR.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>",
          "timestamp": "2025-09-09T22:05:09Z",
          "tree_id": "aa0487027bcf30b9695271fa583b480e4745ee83",
          "url": "https://github.com/sfroment/ethrex/commit/3565e63abdfeb7fdbb7bfd6b40943b0c891cc6eb"
        },
        "date": 1757516718326,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 170666722219,
            "range": "± 472832870",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}