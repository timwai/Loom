#!/usr/bin/env python3
"""Stop only the owned UDP helper and labelled Android lab; retain data."""
import hashlib,json,os,signal,subprocess,time
from pathlib import Path
base=Path('/opt/loom-l001-lab/integrated-20261020')
manifest=json.loads((base/'binary-manifest.json').read_text())
files={**manifest['source_sha256'],**{'bin/'+b['file']:b['sha256'] for b in manifest['binaries']},'bin/linux_channel_lab':manifest['linux_channel_sha256']}
for name,value in files.items():
 assert hashlib.sha256((base/name).read_bytes()).hexdigest()==value,name
result={'payload_files_verified':len(files)}
pid=int(Path('/opt/loom-l001-lab/udp-echo-jni.pid').read_text())
proc=Path('/proc')/str(pid)/'cmdline'
if proc.exists() and proc.read_bytes():
 command=proc.read_bytes()
 assert b'/opt/loom-l001-lab/udp_echo.py' in command and b'172.17.0.1' in command
 os.kill(pid,signal.SIGTERM)
 for _ in range(30):
  if not proc.exists() or not proc.read_bytes(): break
  time.sleep(.1)
result['udp_helper_stopped']=not proc.exists() or not proc.read_bytes()
assert result['udp_helper_stopped']
p=subprocess.run(['python3',str(base/'scripts/l001_android_server_setup.py'),'stop'],capture_output=True,text=True,timeout=60)
result['stop_exit']=p.returncode;result['stop_stdout']=p.stdout;result['stop_stderr']=p.stderr
assert p.returncode==0
result['business']={}
for name in ['relay-agent','aigc_all','aigc_milvus','nginx','loom-l001-android-jp']:
 d=json.loads(subprocess.run(['docker','inspect',name],capture_output=True,text=True,check=True,timeout=15).stdout)[0]
 record={'id':d['Id'],'started_at':d['State']['StartedAt'],'restart_count':d['RestartCount'],'running':d['State']['Running']}
 if name=='loom-l001-android-jp':
  record.update({'exit_code':d['State']['ExitCode'],'oom_killed':d['State']['OOMKilled']})
  result['lab']=record;assert not record['running']
 else: result['business'][name]=record;assert record['running']
result['data_and_image_retained']=True
print(json.dumps(result,indent=2))
