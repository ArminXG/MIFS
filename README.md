# MIFS - Multifile Image File System

MIFS is a FUSE based filesystem which provides just one file in the mounted directory.
This file has a fixed size (configured by commanline parameters) and can be used as
an image or block device via loop.

The content of that image file is split up into chunks of a configurable fixed size. These
chunks are stored in a specified path.

## Purpose

To store a big image file on a storage system that doesn't allow to read/write on
given offsets (always transfers whole file) like SSHFS, WebDav, etc., MIFS allow to
split up a big file into smaller chunks (files).

Example: To create a backup on a cloud based storage, you might want to use an image file
with an encrypted filesysten on it. The image file would be too big as one file on the
cloud storage system or the access to the cloud storage is not able to read/write
on offsets of the file. The image file provided by MIFS stores the image data in many
different files of much smaller size.

## How does it work ?

MIFS is FUSE based. It means you just mount it into some directory of your choice.
You specify the path where to store the smaller chunk files (e.g. cloud storage mount directory).
MIFS will create chunk files only if data is stored on the corresponding image file offset.
If an application tries to read from an offset which was not stored yet (no chunk file), MIFS
returns a buffer of all zeros.
The chunk filenames are either just the number of the offset chuck (based on chunk sizes) or
(if you want to hide the order of the files) sha256 hashed filenames.
To avoid too many files in one directory, MIFS creates automatically subdirs.

## Running it.

To start MIFS and fire up the image file:

  ./mifs -p /path/to/cloudstorage -n myimage.img -S 1G -b 1M /path/to/myimage

This will create the mounted directory

  /path/to/myimage

with the file
 
  /path/to/myimage/myimage.img

The imagefile has a fixed size of 1GB (-S option).
The 1GB space is stored (on writes) here

  /path/to/cloudstorage/x/y

with files (y) of a fixed size 1MB (option -b).
Subdirs (x) are created automatically.

Use

  ./mifs -h

for all MIFS and FUSE options.

!!! Always start MIFS with the same options for the same image file. If
you use other options, your previously stored data is lost. !!!

  
