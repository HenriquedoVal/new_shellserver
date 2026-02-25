This is the new [ShellServer](https://github.com/HenriquedoVal/shellserver).  

Install: 
- Download on Releases
- Extract somewhere on PATH
- The PowerShell client can be installed with `Install-Module NewShellServer -AllowClobber`.
Here is the [source](https://github.com/HenriquedoVal/new-shellserver-clients/tree/main/pwsh).  


Run:
~~~PowerShell
nss_server                    # start server
Import-Module NewShellServer  # start client
~~~


Build with CMake and Ninja:
~~~PowerShell
git clone https://github.com/HenriquedoVal/new_shellserver && cd new_shellserver
git submodule init && git submodule update
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && ninja
# move nss_server.exe and nss_client.dll somewhere on PATH
~~~

If the prompt clutters your screen too much, I suggest using [SinglePrompt](https://github.com/HenriquedoVal/SinglePrompt).
