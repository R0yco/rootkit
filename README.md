# rootkit
a simple rootkit for linux, capable of:
- hiding proccesses
- hiding files
- hiding listening ports
- hiding itself
- blocking traffic by specific IP.

## usage

1) compile rootkit:

   ```bash
   git clone
   cd combined_rootkit
   make
   ```

2. insert rootkit as kernel module:

   ```bash
   sudo insmod ./rootkit.ko [file_to_hide=file pid_to_hide=pid port_to_hide=port ip_to_block=1.1.1.1]
   ```

   the rootkit defaults to only hiding itself from lsmod command.

   if provided with above params, it does those features as well.

   