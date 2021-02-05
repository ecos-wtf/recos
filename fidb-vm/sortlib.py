#!/usr/bin/env python3
import glob
import os
import shutil
root="/tmp/sorted"
version="2"
variant="0"
os.makedirs(root, exist_ok=True)

for name in glob.glob("**/*.o", recursive=True):
    library_path = name.split("v2_0")[0][0:-1]
    elf_name = name.split("/")[-1]
    library_name = library_path.replace("/", "_")
    dest_dir = dest = "{}/{}/{}/{}".format(root, library_name[:-1], version, variant)
    dest_file = "{}/{}".format(dest_dir, elf_name)
    os.makedirs(dest_dir, exist_ok=True)
    print(dest_file)
    shutil.copy2(name, dest_file) # complete target filename given
