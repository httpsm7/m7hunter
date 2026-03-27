#!/usr/bin/env python3
# modules/step20_graphql.py — GraphQL endpoint discovery + introspection
import os, json, urllib.request, urllib.parse
from core.utils import safe_read

class GraphQLStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    ENDPOINTS = [
        "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
        "/graphiql", "/playground", "/api/v1/graphql", "/query",
        "/graphql/console", "/altair", "/gql", "/graph",
    ]

    INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'

    def run(self):
        urls = safe_read(self.f["live_hosts"])[:30]
        out  = self.f["graphql_results"]
        found = 0

        for base_url in urls:
            base_url = base_url.rstrip("/")
            for ep in self.ENDPOINTS:
                url = base_url + ep
                # Check if endpoint exists
                code = self.p.shell(
                    f"curl -sk -o /dev/null -w '%{{http_code}}' "
                    f"--connect-timeout 5 '{url}'")
                if code.strip() not in ("200","400","405"):
                    continue

                # Test introspection
                result = self.p.shell(
                    f"curl -sk --connect-timeout 5 -X POST "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{self.INTROSPECTION}' '{url}' 2>/dev/null")

                line = f"GraphQL: {url}"
                with open(out,"a") as f: f.write(line+"\n")

                if "__schema" in result or "types" in result:
                    self.p.add_finding("high","GRAPHQL_INTROSPECTION",url,
                                       "Introspection enabled — schema exposed","graphql")
                    found += 1
                elif "errors" in result or "data" in result:
                    self.p.add_finding("medium","GRAPHQL_ENDPOINT",url,
                                       "GraphQL endpoint found","graphql")
                    found += 1

                # Test for batching DoS
                batch = '[' + ','.join([self.INTROSPECTION]*10) + ']'
                self.p.shell(
                    f"curl -sk --connect-timeout 5 -X POST "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{batch}' '{url}' -o /dev/null",
                    label=f"graphql batch test {url}")

        self.log.success(f"GraphQL: {found} endpoints")
