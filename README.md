# osrs-launcher
osrs-launcher is an OldSchool RuneScape launcher for Linux, supporting OldSchool and Jagex accounts natively without Wine.  It only contacts Jagex servers directly, just like the native Windows client, so your account remains secure.  

## How to use
### Prepare RuneLite
RuneLite must be runnable with the command `runelite`.  You can do this by creating a wrapper script and placing it in a directory in your PATH, such as `~/.local/bin`:
```sh
#!/bin/sh
java -jar path/to/RuneLite.jar
```
or
```sh
#!/bin/sh
path/to/RuneLite.AppImage
```
and then mark it as executable with `chmod +x ~/.local/bin/runelite`
### Build
Use cargo to build the project
`cargo build -r`
### Install
Move the built binary to a directory in your PATH  
`cp ./target/release/osrs-launcher ~/.local/bin/`  
Give permissions to bind to port 80 for the consent callback  
`setcap 'cap_net_bind_service=+ep' ~/.local/bin/osrs-launcher`  
### Usage
```
Usage: osrs-launcher [OPTIONS]

Options:
  -d, --daemon-port <DAEMON_PORT>  [default: 80]
  -k, --kill-daemon                
  -c, --clear-creds                
  -h, --help                       Print help
```

## Requirements
osrs-launcher can be built with [Cargo, the Rust package manager](https://www.rust-lang.org/).  Build-time dependencies will be automatically downloaded by Cargo.

At runtime, osrs-launcher uses `xdg-open` to open OAuth2 urls for authorization, which should be available in the `xdg-utils` package on Debian systems.  osrs-launcher will also print the url to standard output, from which you can open the URL manually if needed.

## Why?
In an effort to bolster account security, Jagex has begun rolling out "Jagex accounts" for Oldschool RuneScape and RuneScape 3.  These accounts allow for the use of case-sensitive passwords, centralization of game characters to one account, quicker logins, and have in-game benefits such as 20 additional bank slots given to OldSchool characters linked to Jagex accounts.

Despite these good intentions, Jagex has made it clear that ["The Jagex launcher and Jagex Accounts will not be supported on the Linux OS"](https://help.jagex.com/hc/en-gb/articles/13413514881937).  Instead, they link to community guides which [use wine](https://github.com/TormStorm/jagex-launcher-linux) to [run the Jagex launcher](https://www.reddit.com/r/2007scape/comments/uo1ey1/comment/i8dop70/) on [Linux](https://www.youtube.com/watch?v=izLxF_Wwinw).

Unfortunately, in order to install the launcher on Linux, the user must install the launcher on Windows and move the files back over to Linux.  And even then, I have experienced that after launching once correctly, the Jagex launcher will not launch again until its OAuth credentials in AppData are deleted - after which the user must go through the authorization and consent flow once again.

This, at least to me, is not an acceptable modification to the previous standard of equal or similar security being given natively to both Windows and Linux users.  This is made even more disappointing by the fact that the Jagex launcher uses the Chromium Embedded Framework (ostensibly utilized by the [Solid State Networks](https://solidstatenetworks.com/) client) which [supports Linux](https://bitbucket.org/chromiumembedded/cef/wiki/BranchesAndBuilding.md).

To remedy this, I've implemented a client in Rust using a [modified](https://github.com/aitoiaita/oauth2-rs) [oauth2-rs](https://github.com/ramosbugs/oauth2-rs) which contacts Jagex OAuth2 endpoints to request access tokens/session ids which are required to launch the OSRS client with a Jagex account.  This isn't a perfect solution or, honestly, a great piece of software.  It does, however, work (for me at least).