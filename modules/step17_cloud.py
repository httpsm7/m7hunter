#!/usr/bin/env python3
# modules/step17_cloud.py — Cloud asset enumeration (S3/GCP/Azure)
import os, urllib.request

class CloudEnumStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        target = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        parts  = target.split(".")
        brand  = parts[0] if parts else target
        out    = self.f["cloud_results"]
        found  = 0

        # S3 bucket patterns
        s3_names = self._gen_names(brand, target)
        for name in s3_names:
            result = self._check_s3(name)
            if result:
                with open(out,"a") as f: f.write(result+"\n")
                self.p.add_finding("high","OPEN_S3_BUCKET",result,
                                   "Publicly accessible cloud storage","cloud-enum")
                found += 1

        # GCP buckets
        for name in s3_names[:10]:
            result = self._check_gcp(name)
            if result:
                with open(out,"a") as f: f.write(result+"\n")
                self.p.add_finding("high","OPEN_GCP_BUCKET",result,"","cloud-enum")
                found += 1

        # Azure blobs
        for name in s3_names[:10]:
            result = self._check_azure(name)
            if result:
                with open(out,"a") as f: f.write(result+"\n")
                self.p.add_finding("high","OPEN_AZURE_BLOB",result,"","cloud-enum")
                found += 1

        # Also run cloud_enum if available
        self.p.shell(
            f"cloud_enum -k {brand} -k {target} --disable-azure --threads 5 2>/dev/null",
            label="cloud_enum", append_file=out, tool_name="cloud_enum")

        self.log.success(f"Cloud assets: {found} found")

    def _gen_names(self, brand, target):
        """Generate bucket name candidates."""
        suffixes = ["","backup","backups","dev","staging","prod","static","assets",
                    "files","data","logs","media","images","uploads","cdn","api",
                    "-backup","-dev","-staging","-prod","-static","-assets"]
        prefixes = ["","backup-","dev-","staging-","prod-","static-"]
        names = set()
        for suf in suffixes:
            names.add(f"{brand}{suf}")
            names.add(f"{target}{suf}")
        for pre in prefixes:
            names.add(f"{pre}{brand}")
        return list(names)[:40]

    def _check_s3(self, name):
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls:
            try:
                req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/3.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    content = resp.read(200).decode(errors="ignore")
                    if "ListBucketResult" in content:
                        return f"OPEN_S3: {url}"
                    return f"EXISTS_S3: {url}"
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return f"EXISTS_S3_PRIVATE: {url}"
            except Exception:
                pass
        return None

    def _check_gcp(self, name):
        url = f"https://storage.googleapis.com/{name}"
        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/3.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                return f"OPEN_GCP: {url}"
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return f"EXISTS_GCP_PRIVATE: {url}"
        except Exception:
            pass
        return None

    def _check_azure(self, name):
        url = f"https://{name}.blob.core.windows.net"
        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/3.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status in (200, 400):
                return f"EXISTS_AZURE: {url}"
        except Exception:
            pass
        return None
