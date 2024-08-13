# BetterKeyDumper

This is a port of [FullKeyDumper](https://github.com/PretendoNetwork/Full_Key_Dumper) to work inside Aroma.

## Usage

This dumps the console's OTP and the BOSS and IDBE keys from the system and shows them on the screen. When exiting the application, it saves them into files on the root of the SD card:

- OTP: `otp.bin`
- BOSS keys: `boss_keys.bin`
- IDBE keys: `idbe_keys.bin`

## Building

You will need the following dependencies installed: [wut](https://github.com/devkitPro/wut) and [libmocha](https://github.com/wiiu-env/libmocha). After installing them, simply run `make` to build the application.

## Credits

Credits to [Rambo6Glaz](https://github.com/EpicUsername12) for making the initial version of FullKeyDumper.
