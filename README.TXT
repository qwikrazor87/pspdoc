A PSP/ePSP plugin to dump PSP DOCUMENT.DAT manuals to PNG images.

This plugin should work for all 6.XX CFW and Adrenaline.
This plugin is a rewrite of the docdump.prx plugin I wrote a few years back.
Unlike docdump.prx, this plugin dumps all PNG images at once,
rather than once at a time while the images are viewed in VSH.

Place pspdoc.prx in ms0:/seplugins/ and enable in ms0:/seplugins/vsh.txt.
Restart VSH.
In the VSH under Game press Triangle on a game that has a DOCUMENT.DAT in its folder.
Select Software Manual.
The memory stick indicator should blink orange for a few seconds.
The PNG images should be dumped by the time the manual appears.
The images should be dumped to ms0:/DOCS/PSP_<GAME FOLDER>/DOC_XXX.PNG.
