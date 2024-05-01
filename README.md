# Windows 11 Lite
## General Information
This script can be used to lighten a Windows 11 ISO file by removing certain components and configuring others. The modifications are made as close as possible to the vanilla version in order to maintain compatibility.

This script uses PowerShell and DISM.

> [!CAUTION]
> An internet connection is requiered to deploy applications (like VCRedist or web browser).

> [!TIP]
> You're free to use or modify the script as you want (AGPL License). Feedback are also appreciated, they can help me to improve the script and fix bugs.

> [!NOTE]
> By default, the time configuration is noted like this : dd-MM-yyyy and the hour set to 24h (European time format).

## Where can I find original ISO ?

You can download an original ISO of Windows 11 from [Microsoft](https://www.microsoft.com/software-download/windows11) website or build it yourself with [UUP dump](https://uupdump.net/fetchupd.php?arch=amd64&ring=retail).

## What's included ?

### Deleted apps

All Windows bloatware are removed from this image. Only those applications remain :

- AVCEncoderVideoExtension
- DesktopAppInstaller
- DolbyAudioExtensions
- HEIFImageExtension
- HEVCVideoExtension
- MPEG2VideoExtension
- Paint
- RawImageExtension
- ScreenSketch
- SecHealthUI (Windows Defender)
- StorePurchaseApp
- VCLibs
- VP9VideoExtensions
- WebMediaExtensions
- WebpImageExtension
- WindowsCalculator
- WindowsNotepad
- WindowsStore
- WindowsTerminal

Edge and OneDrive are also removed.

> [!NOTE]
> An application can be added or removed from the exclusion list (look at "**Windows bloatware removal**" section).
<br />If Edge reinstalls after an update, you can delete it again from the Control Panel. You can only do it without script if you are in Europe (DMA compliance). If not, I recommend you to use [AveYo Edge Removal](https://github.com/AveYo/fox/blob/main/Edge_Removal.bat) script.


### Telemetry

With registry manipulation, telemetry is disabled. You can see it in the "**Registry : Privacy**" section.

### Performances

With registry manipulation, performances are boosted. Components like background applications or SmartScreen are disabled. You can see it in the "**Registry : Performances**" section.

### Customization

With registry manipulation, I have customized some parts of Windows like restoring old context menu or enabling folders by default on Start Menu. You can see it in the "**Registry : Customization**" section.

## What's next ?

It is currently planned to include all necessary modifications in future Windows updates. When Microsoft rolls out an update that introduces an unwanted feature (e.g. advertising), I'll include the appropriate changes.

As far as application integrations are concerned, here's what's planned :

- Choosing an additional browser : [Ungoogled-Chromium](https://github.com/macchrome/winchrome/) and [updater](https://github.com/mkorthof/chrupd) integration

> [!NOTE]
> I can add some specific browser ADMX in a seperate file. You can check and add them to the main script if you want to deploy a specific browser configuration.

## Credits

- **[George King](https://www.ntlite.com/community/index.php?members/george-king.5/)** for the OOBE.cmd and Watcher.cmd script
- **[Chris Wu](https://github.com/TheDotSource/New-ISOFile)** for New-IsoFile function
- **[ntdevlabs](https://github.com/ntdevlabs/tiny11builder)** for the script structuring model (Based on tiny11builder template)
- **[Matt](https://stackoverflow.com/users/1016343/matt)** for the cmd elevation script
