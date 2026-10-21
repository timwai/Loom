#!/usr/bin/env python3
"""Read only lab health and minimal existing-container identity fields."""
import datetime,json,subprocess

def run(*args, expected=0):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 if p.returncode!=expected: raise RuntimeError(str(args)+': '+p.stderr)
 return p.stdout.strip()

def inspect(name): return json.loads(run('docker','inspect',name))[0]
lab=inspect('loom-l001-android-jp')
assert lab['Config'].get('Labels',{}).get('loom.task')=='l001-android-remote'
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'business':{}}
for name in ['relay-agent','aigc_all','aigc_milvus','nginx']:
 d=inspect(name)
 result['business'][name]={'id':d['Id'],'started_at':d['State']['StartedAt'],'restart_count':d['RestartCount'],'running':d['State']['Running']}
result['lab']={'id':lab['Id'],'image':lab['Image'],'running':lab['State']['Running'],'started_at':lab['State']['StartedAt'],'restart_count':lab['RestartCount'],'oom_killed':lab['State']['OOMKilled'],'resources':{k:lab['HostConfig'][k] for k in ['NanoCpus','Memory','PidsLimit']}}
result['pressure']=run('cat','/proc/pressure/memory')
result['framework']={}
for key,args in {
 'boot':['getprop','sys.boot_completed'],'lmkd':['getprop','init.svc.lmkd'],
 'system_server_pid':['pidof','system_server'],'memory_events':['cat','/sys/fs/cgroup/memory.events'],
 'pids_events':['cat','/sys/fs/cgroup/pids.events'],'interfaces':['ip','-o','link','show']}.items():
 result['framework'][key]=run('docker','exec','loom-l001-android-jp',*args)
p=subprocess.run(['docker','exec','loom-l001-android-jp','pidof','fun.loom.lab'],capture_output=True,text=True,timeout=15)
result['framework']['app_pid']=p.stdout.strip();result['framework']['app_pid_exit']=p.returncode
print(json.dumps(result,indent=2))
