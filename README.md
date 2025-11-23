# zISO Tweaker
Create your own custom Windows 11 ISO using PowerShell!

## How to Use
- First download or clone the repository, for most users simply click the green `Code` button on the top right and select `Download ZIP`, extract the files and run `Run-ISOTweaker.cmd` as Administrator
- Download an ISO file to modify, you can either download the latest 25H2 release ISO from [Massgrave](https://massgrave.dev/windows_11_links) or [UUP Dump](https://uupdump.net/)
  - When using the above options provided by the script the Massgrave ISO will include all the default editions, when using UUP dump option you can choose 23H2,24H2, or 25H2 all using Enterprise Edition
>[!TIP]
> 
> I recommend using Enterprise as this ensures all Group Policy tweaks work properly
> 
>
- After selecting the edition you want to use, simply choose the tweaks and wait for the script to create your custom ISO

### Video Guide:
https://youtu.be/Us8LbeQwOfc

## Tweaks Applied By Default
- Some tweaks are applied to the ISO for everyone and do not have an option to select them:
  - Disable Windows 11 Install Requirements
  - Disable Microsoft Account Requirement
  - Disable auto install of Teams and New Outlook
  - Disable Windows Platform Binary Table and CoInstallers to prevent auto install of unwanted software
  - Disable Customer Experience Program
  - Disable and remove Cross Device Resume
  - Disable all Content Delivery
  - Remove First Logon Screen after OOBE
  - Enable Windows 10 Context Menu
  - Removes bloat pinned to taskbar and startmenu by default
  - Disable User Choice Driver
  - Disable Windows Quality and Health Insights services
  - Disable Windows Update Check in OOBE
 
## UI Demo

<img width="686" height="493" alt="{58BB84CA-0BA6-49D8-8E51-F2806B80249F}" src="https://github.com/user-attachments/assets/e12a83b3-f899-4e9d-9e25-7678f155f1f6" />
<img width="682" height="460" alt="{AE62C713-9BE3-44AB-9A82-0B29E39F1630}" src="https://github.com/user-attachments/assets/4e75a0d5-5ecd-408c-9b8b-98c46340ebba" />
