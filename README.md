## pixel_loader

This is an IDA Pro loader, that can help improve the process of reversing the ABL stage of the Pixel phone bootloader.

Simply copy the script to the following path:
```
$IDAPRO/loaders/
```

Where $IDAPRO is the folder/directory where the ida executable is located.
For example on Windows that would be something like ```C:\Program Files\IDA Pro 8.3\loaders\```

So, far the loader will help with:
  - Finding the function table (containing offests of where the functions .
  are, their size and an offset to their name as null-terminiated string).
  - Creating some C-style structs and applying.
  - Marking interesting areas in the bootloader binary.

It will be updated later to include improved function types/identifying embedded objects...etc to help in reverse engineering and research.

### Example

Before the loader IDA pro tries to auto-gess where the valid instructions are (This image is from IDA Pro 8.3)

![Example 1](./screenshot/idapro83-abl.PNG)

After the loader has been installed, this is the results:

![Example 1](./screenshot/idapro83-abl2.PNG)

