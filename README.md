This is the new [ShellServer](https://github.com/HenriquedoVal/shellserver).  
Provides custom prompt and navigation features.

### Install: 

- Download the server from Releases
- Extract somewhere on PATH

<details>
<summary>PowerShell client</summary>

~~~PowerShell
Install-Module NewShellServer -AllowClobber
~~~
Here is the [source](https://github.com/HenriquedoVal/sspwsh).  
</details>

<details>
<summary>Neovim client</summary>

With Lazy, add this to your plugins:
~~~lua
	{
        "HenriquedoVal/ssnvim",
        cmd = "P"
	},
~~~
Here is the [source](https://github.com/HenriquedoVal/ssnvim).  
</details>

### Run:

~~~PowerShell
nss_server                    # start server
Import-Module NewShellServer  # start client
~~~


### Usage:

<details>
<summary><code>p</code>, alias for <code>Set-ShellServerLocation</code></summary>

The server will add the last portion of the paths you walk as a "refpath" so
you can later `p <refpath>` to jump there. Acts like `cd` for relative or
absolute paths.  
  
Syntax:
- `p [PathOrRefpath] [-j] [-o]`, alias for:
- `Set-ShellServerLocation [[-PathOrRefpath] string] [-Output] [-Junction]`

Options:
- `-j`: Jump to the junction of the current directory or resolved refpath.
- `-o`: Resolves refpath and sends result to pipeline. Useful for cmds like `move file.txt (p -o refpath)`.

---
</details>


<details>
<summary><code>pe</code>, alias for <code>Edit-ShellServerCache</code></summary>

Cmdlet to manage the state of the refpaths cache.  
  
Syntax:
- `pe [-a path [-as string]] [-d path] [-dr refpath] [-md refpath]`, alias for:
- `Edit-ShellServerCache [-Add <string> [-As <string>]] [-DelPath <string>] [-DelRef <string>] [-MoveDown <string>]`

Options:
- `-a`: Adds path to cache. Adds `-as` given name if provided.
- `-d`: Deletes the first given relative or absolute path from cache.
- `-dr`: Deletes the first given "refpath" from cache.
- `-md`: Moves given refpath to the last entry of cache.

---
</details>


<details>
<summary><code>Show-ShellServerCache</code></summary>

Shows current cache status.  
  
Syntax:
- `Show-ShellServerCache [-Stored]`

Options:
- `-Stored`: Shows cache stored in the filesystem instead of the one in memory.

---
</details>


<details>
<summary><code>Save-ShellServerCache</code></summary>

Writes to the filesystem the current state of the cache. Saves in `$env:localappdata\ShellServer\nss.dat`.
This file is loaded on server startup.

---
</details>

<details>
<summary>Neovim <code>P</code> command</summary>

Same as `p` alias for PowerShell. Just `:P <refpath>` to jump there.

---
</details>

### Differences from older ShellServer

- The cleaning of the previous prompt was moved to its own (much better) module [SinglePrompt](https://github.com/HenriquedoVal/SinglePrompt).
- Theme management became a CLI program [wtheme](https://github.com/HenriquedoVal/wtheme).
- Removed history search. You can just `sls <query> -r (Get-PSReadLineOption | select -exp HistorySavePath)`.
- Removed useless custom directory listing.
- `pz` is not supported here, and it was a very useful feature...
- Overall bloat removed


### Build with CMake and Ninja:

~~~PowerShell
git clone https://github.com/HenriquedoVal/new_shellserver && cd new_shellserver
git submodule init && git submodule update
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && ninja
# move nss_server.exe and nss_client.dll somewhere on PATH
~~~
