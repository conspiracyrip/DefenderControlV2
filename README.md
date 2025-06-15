# DefenderControlV2
forked &amp; better verison of defender-control by pgkt04 with more features.

# Open source windows defender disabler.
Now you can disable windows defender permanently!
Tested on Windows 10 22H2 & Windows 11 24H2.

## What is this project?  
We all know that disabling windefender is very difficult since microsoft is constantly enforcing changes.  
The first solution is to install an anti-virus - but thats not the point if we are trying to disable it!  
The second is blowing up Microsoft HQ, but this isn't cost effective and i don't like the feds.  
The next easiest solution is to use freeware thats already available on the internet - but none of them are native & open source...  
I like open source, so I made a safe to use open source defender control.  

# Notes
On windows updates / Windows 11

Sometimes windows decides to update and turn itself back on.
A common issue is that defender control sometimes doesn't want to disable tamper protection again.
Please try turning off tamper protection manually then running disable-defender.exe again before posting an issue.

# What the flip does it do?
    It gains TrustedInstaller permissions
    It will disable windefender services + smartscreen
    It will disable anti-tamper protection
    It will handle WdFilter
    It will disable all relevant registries + wmi settings
# this is based on defender-control by pgkt04? but what is different?
unlike the original version, https://github.com/pgkt04/defender-control.
this has better handling, sane error protection, and removes the files (C:\Program Files\Windows Defender, C:\Program Files (x86)\Windows Defender reversible though not implemented currently)
this also handles WdFilter properly and leaves its filter off, along with handling smartscreen for performance, and instead of setting to manual (fuck windows) we set to 4 (truly disabled)

# i hate Microsoft please kill yourselves if you handle windefend.

# anyways enjoy i guess. <3
