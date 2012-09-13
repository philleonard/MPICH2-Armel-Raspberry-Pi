# MPICH2 Release 1.4.1p1

MPICH2 is a high-performance and widely portable implementation of the
MPI-2.2 standard from the Argonne National Laboratory. This release
has all MPI 2.2 functions and features required by the standard with
the exception of support for the "external32" portable I/O format and
user-defined data representations for I/O.

The distribution has been tested by us on a variety of machines in our
environments as well as our partner institutes. If you have problems
with the installation or usage of MPICH2, please send an email to
mpich-discuss@mcs.anl.gov (you need to subscribe to this list
(https://lists.mcs.anl.gov/mailman/listinfo/mpich-discuss) before
sending an email). If you have found a bug in MPICH2, we request that
you report it at our bug tracking system:
(https://trac.mcs.anl.gov/projects/mpich2/newticket).

This README file should contain enough information to get you started
with MPICH2. More extensive installation and user guides can be found
in the doc/installguide/install.pdf and doc/userguide/user.pdf files
respectively. Additional information regarding the contents of the
release can be found in the CHANGES file in the top-level directory,
and in the RELEASE_NOTES file, where certain restrictions are
detailed. Finally, the MPICH2 web site,
http://www.mcs.anl.gov/research/projects/mpich2, contains information
on bug fixes and new releases.

  1. Getting Started
  2. Compiler Flags
  3. Alternate Channels and Devices
  4. Alternate Process Managers
  5. Alternate Configure Options
  6. Testing the MPICH2 installation
  7. Fault Tolerance
  8. Environment Variables
  9. Developer Builds
  10. Installing MPICH2 on windows
  11. Multiple Fortran compiler support

-------------------------------------------------------------------------

1. Getting Started
==================

The following instructions take you through a sequence of steps to get
the default configuration (ch3 device, nemesis channel (with TCP and
shared memory), Hydra process management) of MPICH2 up and running.

(a) You will need the following prerequisites.

    - REQUIRED: This tar file mpich2-1.4.1p1.tar.gz

    - REQUIRED: A C compiler (gcc is sufficient)

    - OPTIONAL: A C++ compiler, if C++ applications are to be used
      (g++, etc.). If you do not require support for C++ applications,
      you can disable this support using the configure option
      --disable-cxx (configuring MPICH2 is described in step 1(d)
      below).

    - OPTIONAL: A Fortran 77 compiler, if Fortran 77 applications are
      to be used (gfortran, ifort, etc.). If you do not require
      support for Fortran 77 applications, you can disable this
      support using --disable-f77 (configuring MPICH2 is described in
      step 1(d) below).

    - OPTIONAL: A Fortran 90 compiler, if Fortran 90 applications are
      to be used (gfortran, ifort, etc.). If you do not require
      support for Fortran 90 applications, you can disable this
      support using --disable-fc. Note that Fortran 77 support is a
      prerequisite for Fortran 90 support (configuring MPICH2 is
      described in step 1(d) below).

    Also, you need to know what shell you are using since different shell
    has different command syntax. Command "echo $SHELL" prints out the
    current shell used by your terminal program.

(b) Unpack the tar file and go to the top level directory:

      tar xzf mpich2-1.4.1p1.tar.gz
      cd mpich2-1.4.1p1

    If your tar doesn't accept the z option, use

      gunzip mpich2-1.4.1p1.tar.gz
      tar xf mpich2-1.4.1p1.tar
      cd mpich2-1.4.1p1

(c) Choose an installation directory, say
    /home/<USERNAME>/mpich2-install, which is assumed to non-existent
    or empty. It will be most convenient if this directory is shared
    by all of the machines where you intend to run processes. If not,
    you will have to duplicate it on the other machines after
    installation.

(d) Configure MPICH2 specifying the installation directory:

    for csh and tcsh:

      ./configure --prefix=/home/<USERNAME>/mpich2-install |& tee c.txt

    for bash and sh:

      ./configure --prefix=/home/<USERNAME>/mpich2-install 2>&1 | tee c.txt

    Bourne-like shells, sh and bash, accept "2>&1 |". Csh-like shell,
    csh and tcsh, accept "|&". If a failure occurs, the configure
    command will display the error. Most errors are straight-forward
    to follow. For example, if the configure command fails with:

       "No Fortran 77 compiler found. If you don't need to build any
        Fortran programs, you can disable Fortran support using
        --disable-f77 and --disable-fc. If you do want to build
        Fortran programs, you need to install a Fortran compiler such
        as gfortran or ifort before you can proceed."

    ... it means that you don't have a Fortran compiler :-). You will
    need to either install one, or disable Fortran support in MPICH2.

    If you are unable to understand what went wrong, please go to step
    1(i) below, for reporting the issue to the MPICH2 developers and
    other users.

(e) Build MPICH2:

    for csh and tcsh:

      make |& tee m.txt

    for bash and sh:

      make 2>&1 | tee m.txt

    This step should succeed if there were no problems with the
    preceding step. Check file m.txt. If there were problems, do a
    "make clean" and then run make again with V=1.

      make V=1 |& tee m.txt (for csh and tcsh)

      OR

      make V=1 2>&1 | tee m.txt (for bash and sh)

    Then go to step 1(i) below, for reporting the issue to the MPICH2
    developers and other users.

(f) Install the MPICH2 commands:

    for csh and tcsh:

      make install |& tee mi.txt

    for bash and sh:

      make install 2>&1 | tee mi.txt

    This step collects all required executables and scripts in the bin
    subdirectory of the directory specified by the prefix argument to
    configure.

(g) Add the bin subdirectory of the installation directory to your
    path in your startup script (.bashrc for bash, .cshrc for csh,
    etc.):

    for csh and tcsh:

      setenv PATH /home/<USERNAME>/mpich2-install/bin:$PATH

    for bash and sh:
  
      PATH=/home/<USERNAME>/mpich2-install/bin:$PATH ; export PATH

    Check that everything is in order at this point by doing:

      which mpicc
      which mpiexec

    These commands should display the path to your bin subdirectory of
    your install directory.

    IMPORTANT NOTE: The install directory has to be visible at exactly
    the same path on all machines you want to run your applications
    on. This is typically achieved by installing MPICH2 on a shared
    NFS file-system. If you do not have a shared NFS directory, you
    will need to manually copy the install directory to all machines
    at exactly the same location.

(h) MPICH2 uses a process manager for starting MPI applications. The
    process manager provides the "mpiexec" executable, together with
    other utility executables. MPICH2 comes packaged with multiple
    process managers; the default is called Hydra.

    Now we will run an MPI job, using the mpiexec command as specified
    in the MPI-2 standard. There are some examples in the install
    directory, which you have already put in your path, as well as in
    the directory mpich2-1.4.1p1/examples. One of them is the
    classic CPI example, which computes the value of pi by numerical
    integration in parallel.

    To run the CPI example with 'n' processes on your local machine,
    you can use:

      mpiexec -n <number> ./examples/cpi

    Test that you can run an 'n' process CPI job on multiple nodes:

      mpiexec -f machinefile -n <number> ./examples/cpi

    The 'machinefile' is of the form:

      host1
      host2:2
      host3:4 # Random comments
      host4:1

    'host1', 'host2', 'host3' and 'host4' are the hostnames of the
    machines you want to run the job on. The ':2', ':4', ':1' segments
    depict the number of processes you want to run on each node. If
    nothing is specified, ':1' is assumed.

    More details on interacting with Hydra can be found at
    http://wiki.mcs.anl.gov/mpich2/index.php/Using_the_Hydra_Process_Manager

If you have completed all of the above steps, you have successfully
installed MPICH2 and run an MPI example.

(i) If you run into any errors configuring, building or running
MPICH2, please send the below files to mpich-discuss@mcs.anl.gov.
PLEASE COMPRESS BEFORE SENDING, AS THE FILES CAN BE LARGE. Note that,
depending on which step the build failed, some of the files might not
exist.

    mpich2-1.4.1p1/c.txt (generated in step 1(d) above)
    mpich2-1.4.1p1/m.txt (generated in step 1(e) above)
    mpich2-1.4.1p1/mi.txt (generated in step 1(f) above)
    mpich2-1.4.1p1/config.log (generated in step 1(d) above)
    mpich2-1.4.1p1/src/openpa/config.log (generated in step 1(d) above)

More details on arguments to mpiexec are given in the User's Guide in
the doc subdirectory.

-------------------------------------------------------------------------

2. Compiler Flags
=================

MPICH2 allows several sets of compiler flags to be used. The first
three sets are configure-time options for MPICH2, while the fourth is
only relevant when compiling applications with mpicc and friends.

(a) CFLAGS, CPPFLAGS, CXXFLAGS, FFLAGS, FCFLAGS, LDFLAGS and LIBS
(abbreviated as xFLAGS): Setting these flags would result in the
MPICH2 library being compiled/linked with these flags and the flags
internally being used in mpicc and friends.

(b) MPICH2LIB_CFLAGS, MPICH2LIB_CPPFLAGS, MPICH2LIB_CXXFLAGS,
MPICH2LIB_FFLAGS, MPICH2LIB_FCFLAGS, MPICH2LIB_LDFLAGS and
MPICH2LIB_LIBS (abbreviated as MPICH2LIB_xFLAGS): Setting these flags
would result in the MPICH2 library being compiled/linked with these
flags. However, these flags will *not* be used by mpicc and friends.

(c) MPICH2_MAKE_CFLAGS: Setting these flags would result in MPICH2's
configure tests to not use these flags, but the makefile's to use
them. This is a temporary hack for certain cases that advanced
developers might be interested in, but which break existing configure
tests (e.g., -Werror). These are NOT recommended for regular users.

(d) MPICH2_MPICC_FLAGS, MPICH2_MPICPP_FLAGS, MPICH2_MPICXX_FLAGS,
MPICH2_MPIF77_FLAGS, MPICH2_MPIFC_FLAGS, MPICH2_LDFLAGS and
MPICH2_LIBS (abbreviated as MPICH2_MPIX_FLAGS): These flags do *not*
affect the compilation of the MPICH2 library itself, but will be
internally used by mpicc and friends.


  +--------------------------------------------------------------------+
  | | | |
  | | MPICH2 library | mpicc and friends |
  | | | |
  +--------------------+----------------------+------------------------+
  | | | |
  | xFLAGS | Yes | Yes |
  | | | |
  +--------------------+----------------------+------------------------+
  | | | |
  | MPICH2LIB_xFLAGS | Yes | No |
  | | | |
  +--------------------+----------------------+------------------------+
  | | | |
  | MPICH2_MAKE_xFLAGS | Yes | No |
  | | | |
  +--------------------+----------------------+------------------------+
  | | | |
  | MPICH2_MPIX_FLAGS | No | Yes |
  | | | |
  +--------------------+----------------------+------------------------+


All these flags can be set as part of configure command or through
environment variables.


Default flags
--------------
By default, MPICH2 automatically adds certain compiler optimizations
to MPICH2LIB_CFLAGS. The currently used optimization level is -O2.

** IMPORTANT NOTE: Remember that this only affects the compilation of
the MPICH2 library and is not used in the wrappers (mpicc and friends)
that are used to compile your applications or other libraries.

This optimization level can be changed with the --enable-fast option
passed to configure. For example, to build an MPICH2 environment with
-O3 for all language bindings, one can simply do:

  ./configure --enable-fast=O3

Or to disable all compiler optimizations, one can do:

  ./configure --disable-fast

For more details of --enable-fast, see the output of "configure
--help".


Examples
--------

Example 1:

  ./configure --disable-fast MPICH2LIB_CFLAGS=-O3 MPICH2LIB_FFLAGS=-O3 \
        MPICH2LIB_CXXFLAGS=-O3 MPICH2LIB_FCFLAGS=-O3

This will cause the MPICH2 libraries to be built with -O3, and -O3
will *not* be included in the mpicc and other MPI wrapper script.

Example 2:

  ./configure --disable-fast CFLAGS=-O3 FFLAGS=-O3 CXXFLAGS=-O3 FCFLAGS=-O3

This will cause the MPICH2 libraries to be built with -O3, and -O3
will be included in the mpicc and other MPI wrapper script.

Example 3:

There are certain compiler flags that should not be used with MPICH2's
configure, e.g. gcc's -Werror, which would confuse configure and cause
certain configure tests to fail to detect the correct system features.
To use -Werror in building MPICH2 libraries, you can pass the compiler
flags during the make step through the Makefile variable
MPICH2_MAKE_CFLAGS as follows:

  make MPICH2_MAKE_CFLAGS="-Wall -Werror"

The content of MPICH2_MAKE_CFLAGS is appended to the CFLAGS in all
relevant Makefiles.

-------------------------------------------------------------------------

3. Alternate Channels and Devices
=================================

The communication mechanisms in MPICH2 are called "devices". MPICH2
supports several internal devices including ch3 (default), dcmfd (for
Blue Gene/P) and globus (for Globus), as well as many third-party
devices that are released and maintained by other institutes such as
osu_ch3 (from Ohio State University for InfiniBand and iWARP), ch_mx
(from Myricom for Myrinet MX), etc.

                   *************************************

ch3 device
**********
The ch3 device contains different internal communication options
called "channels". We currently support nemesis (default) and sock
channels, and experimentally provide a dllchan channel within the ch3
device.

nemesis channel
---------------
Nemesis provides communication using different networks (tcp, mx) as
well as various shared-memory optimizations. To configure MPICH2 with
nemesis, you can use the following configure option:

  --with-device=ch3:nemesis

The TCP network module gets configured in by default. To specify a
different network module such as MX, you can use:

  --with-device=ch3:nemesis:mx

If the MX include files and libraries are not in the normal search
paths, you can specify them with the following options:

  --with-mx-include= and --with-mx-lib=

... or the if lib/ and include/ are in the same directory, you can use
the following option:

  --with-mx=

If the MX libraries are shared libraries, they need to be in the
shared library search path. This can be done by adding the path to
/etc/ld.so.conf, or by setting the LD_LIBRARY_PATH variable in your
.bashrc (or .tcshrc) file. It's also possible to set the shared
library search path in the binary. If you're using gcc, you can do
this by adding

  LD_LIBRARY_PATH=/path/to/lib

  (and)

  LDFLAGS="-Wl,-rpath -Wl,/path/to/lib"

... as arguments to configure.

By default, MX allows for only eight endpoints per node causing
ch3:nemesis:mx to give initialization errors with greater than 8
processes on the same node (this is an MX error and not an inherent
limitation in the MPICH2/Nemesis design). If needed, this can be set
to a higher number when MX is loaded. We recommend the user to contact
help@myri.com for details on how to do this.

Shared-memory optimizations are enabled by default to improve
performance for multi-processor/multi-core platforms. They can be
disabled (at the cost of performance) either by setting the
environment variable MPICH_NO_LOCAL to 1, or using the following
configure option:

  --enable-nemesis-dbg-nolocal

The --with-shared-memory= configure option allows you to choose how
Nemesis allocates shared memory. The options are "auto", "sysv", and
"mmap". Using "sysv" will allocate shared memory using the System V
shmget(), shmat(), etc. functions. Using "mmap" will allocate shared
memory by creating a file (in /dev/shm if it exists, otherwise /tmp),
then mmap() the file. The default is "auto". Note that System V
shared memory has limits on the size of shared memory segments so
using this for Nemesis may limit the number of processes that can be
started on a single node.

sock channel
------------
sock is the traditional TCP sockets based communication channel. It
uses TCP/IP sockets for all communication including intra-node
communication. So, though the performance of this channel is worse
than that of nemesis, it should work on almost every platform. This
channel can be configured using the following option:

  --with-device=ch3:sock

sctp channel
------------
The SCTP channel is a new channel using the Stream Control
Transmission Protocol (SCTP). This channel supports regular MPI-1
operations as well as dynamic processes and RMA from MPI-2; it
currently does not offer support for multiple threads.

Configure the sctp channel by using the following option:

  --with-device=ch3:sctp

If the SCTP include files and libraries are not in the normal search
paths, you can specify them with the --with-sctp-include= and
--with-sctp-lib= options, or the --with-sctp= option if lib/ and
include/ are in the same directory.

SCTP stack specific instructions:

  For FreeBSD 7 and onward, SCTP comes with CURRENT and is enabled with
  the "option SCTP" in the kernel configuration file. The sctp_xxx()
  calls are contained within libc so to compile ch3:sctp, make a soft-link
  named libsctp.a to the target libc.a, then pass the path of the
  libsctp.a soft-link to --with-sctp-lib.
  
  For FreeBSD 6.x, kernel patches and instructions can be downloaded at
  http://www.sctp.org/download.html . These kernels place libsctp and
  headers in /usr, so nothing needs to be specified for --with-sctp
  since /usr is often in the default search path.

  For Mac OS X, the SCTP Network Kernel Extension (NKE) can be
  downloaded at http://sctp.fh-muenster.de/sctp-nke.html . This places
  the lib and include in /usr, so nothing needs to be specified for
  --with-sctp since /usr is often in the default search path.

  For Linux, SCTP comes with the default kernel from 2.4.23 and later as
  a module. This module can be loaded as root using "modprobe sctp".
  After this is loaded, you can verify it is loaded using "lsmod".
  Once loaded, the SCTP socket lib and include files must be downloaded
  and installed from http://lksctp.sourceforge.net/ . The prefix
  location must then be passed into --with-sctp. This bundle is called
  lksctp-tools and is available for download off their website.

  For Solaris, SCTP comes with the default Solaris 10 kernel; the lib
  and include in /usr, so nothing needs to be specified for --with-sctp
  since /usr is often in the default search path. In order to compile
  under Solaris, MPICH2LIB_CFLAGS must have
  -DMPICH_SCTP_CONCATENATES_IOVS set when running MPICH2's configure
  script.

                   *************************************

IBM Blue Gene/P device
**********************
MPICH2 also supports the IBM Blue Gene/P systems. Since BG/P's
front-end uses a different architecture than the actual compute nodes,
MPICH2 has to be cross-compiled for this platform. The configuration
of MPICH2 on BG/P relies on the availability of the DCMF driver stack
and cross compiler binaries on the system. These are packaged by IBM
in their driver releases (default installation path is
/bgsys/drivers/ppcfloor) and are not released with MPICH2.

Assuming DRIVER_PATH points to the driver installation path (e.g.,
/bgsys/drivers/ppcfloor), the following is an example configure
command-line for MPICH2:

  GCC=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-gcc \
  CC=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-gcc \
  CXX=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-g++ \
  F77=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-gfortran \
  FC=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-gfortran \
  CFLAGS="-mcpu=450fp2" \
  CXXFLAGS="-mcpu=450fp2" \
  FFLAGS="-mcpu=450fp2" \
  FCFLAGS="-mcpu=450fp2" \
  AR=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-ar \
  LD=${DRIVER_PATH}/gnu-linux/bin/powerpc-bgp-linux-ld \
  MSGLAYER_INCLUDE="-I${DRIVER_PATH}/comm/include" \
  MSGLAYER_LIB="-L${DRIVER_PATH}/comm/lib -ldcmfcoll.cnk -ldcmf.cnk -lpthread -lrt \
      -L$DRIVER_PATH/runtime/SPI -lSPI.cna" \
  ./configure --with-device=dcmfd:BGP --with-pmi=no --with-pm=no --with-file-system=bgl \
   --enable-timer-type=device --with-cross=src/mpid/dcmfd/cross \
--host=powerpc-bgp-linux --target=powerpc-bgp-linux --build=powerpc64-linux-gnu

-------------------------------------------------------------------------

4. Alternate Process Managers
=============================

hydra
-----
Hydra is the default process management framework that uses existing
daemons on nodes (e.g., ssh, pbs, slurm, sge) to start MPI
processes. More information on Hydra can be found at
http://wiki.mcs.anl.gov/mpich2/index.php/Using_the_Hydra_Process_Manager

mpd
---
MPD was the traditional process manager in MPICH2. The file
mpich2-1.4.1p1/src/pm/mpd/README has more information about
interactive commands for managing the ring of MPDs. The MPD process
manager is now deprecated.

smpd
----
SMPD is a process manager for interoperability between Microsoft
Windows and UNIX, where some processes are running on Windows and
others are running on a variant of UNIX. For more information, please
see mpich2-1.4.1p1/src/pm/smpd/README.

gforker
-------

gforker is a process manager that creates processes on a single
machine, by having mpiexec directly fork and exec them. gforker is
mostly meant as a research platform and for debugging purposes, as it
is only meant for single-node systems.

slurm
-----
SLURM is an external process manager not distributed with
MPICH2. However, we provide configure options that allow integration
with SLURM. To enable this support, use "--with-pmi=slurm
--with-pm=no" option with configure.

-------------------------------------------------------------------------

5. Alternate Configure Options
==============================

MPICH2 has a number of other features. If you are exploring MPICH2 as
part of a development project, you might want to tweak the MPICH2
build with the following configure options. A complete list of
configuration options can be found using:

   ./configure --help

However, for your convenience, we list a few important options here:

Performance Options:

 --enable-fast - Turns off error checking and collection of internal
                 timing information

 --enable-timing=no - Turns off just the collection of internal timing
                      information

 --enable-ndebug - Turns on NDEBUG, which disables asserts. This is a
                   subset of the optimizations provided by
                   enable-fast, but is useful in environments where
                   the user wishes to retain the debug symbols, e.g.,
                   this can be combined with the --enable-g option.

MPI Features:

  --enable-romio - Build the ROMIO implementation of MPI-IO (enabled
                   by default).

  --with-file-system - When used with --enable-romio, specifies
                       filesystems ROMIO should support. They can be
                       specified by passing them in a '+'-delimited
                       list: (e.g.,
                       --with-file-system="pvfs+nfs+ufs").

                       If you have installed version 2 of the PVFS
                       file system, you can use the
                       '--with-pvfs2=<prefix>' configure option to
                       specify where libraries, headers, and utilities
                       have been installed. If you have added the pvfs
                       utilities to your PATH, then ROMIO will detect
                       this and build support for PVFS automatically.

  --enable-threads - Build MPICH2 with support for multi-threaded
                     applications. Only the sock and nemesis channels
                     support MPI_THREAD_MULTIPLE.

  --with-thread-package - When used with --enable-threads, this option
                          specifies the thread package to use. This
                          option defaults to "posix". At the moment,
                          only POSIX threads are supported on UNIX
                          platforms. We plan to support Solaris
                          threads in the future.

Language bindings:

  --enable-f77 - Build the Fortran 77 bindings (enabled by default).

  --enable-fc - Build the Fortran 90 bindings (enabled by default).

  --enable-cxx - Build the C++ bindings (enabled by default).

Shared library support:

  --enable-shared - Enable shared library support. Shared libraries
                    are currently only supported for gcc (and gcc-like
                    compilers) on Linux and Mac and for cc on
                    Solaris. To have shared libraries created when
                    MPICH2 is built, specify the following when MPICH2
                    is configured:

  For users who wish to manually control the linker parameters, this
  can be done using:

  --enable-sharedlibs=gcc (on Linux)
  --enable-sharedlibs=osx-gcc (on Mac OS X)
  --enable-sharedlibs=solaris-cc (on Solaris)

Cross compilation:

  --with-cross=filename - Provide values for the tests that required
                          running a program, such as the tests that
                          configure uses to determine the sizes of the
                          basic types. This should be a fine in
                          Bourne shell format containing variable
                          assignment of the form

                          CROSS_SIZEOF_INT=2

                          for all of the CROSS_xxx variables.

Error checking and reporting:

  --enable-error-checking=level - Control the amount of error
                                  checking. Currently, only "no" and
                                  "all" is supported; all is the
                                  default.

  --enable-error-messages=level - Control the aount of detail in error
                                  messages. By default, MPICH2
                                  provides instance-specific error
                                  messages; but, with this option,
                                  MPICH2 can be configured to provide
                                  less detailed messages. This may be
                                  desirable on small systems, such as
                                  clusters built from game consoles or
                                  high-density massively parallel
                                  systems. This is still under active
                                  development.

Compilation options for development:

  --enable-g=value - Controls the amount of debugging information
                     collected by the code. The most useful choice
                     here is dbg, which compiles with -g.

  --enable-coverage - An experimental option that enables GNU coverage
                      analysis.

  --with-logging=name - Select a logging library for recording the
                        timings of the internal routines. We have
                        used this to understand the performance of the
                        internals of MPICH2. More information on the
                        logging options, capabilities and usage can be
                        found in doc/logging/logging.pdf.

  --enable-timer-type=name - Select the timer to use for MPI_Wtime and
                             internal timestamps. name may be one of:
                     gethrtime - Solaris timer (Solaris systems
                                        only)
                     clock_gettime - Posix timer (where available)
                     gettimeofday - Most Unix systems
                     linux86_cycle - Linux x86; returns cycle
                                        counts, not time in seconds*
                     linuxalpha_cycle - Like linux86_cycle, but for
                                        Linux Alpha*
                     gcc_ia64_cycle - IPF ar.itc timer*
                     device - The timer is provided by the device
                 *Note that the cycle timers are intended to be used by
                  MPICH2 developers for internal low-level timing.
                  Normal users should not use these as they are not
                  guaranteed to be accurate in certain situations.

-------------------------------------------------------------------------

6. Testing the MPICH2 installation
==================================

To test MPICH2, we package the MPICH2 test suite in the MPICH2
distribution. You can run the test suite using:

     make testing

The results summary will be placed in test/summary.xml

-------------------------------------------------------------------------

7. Fault Tolerance
==================

MPICH2 has some tolerance to process failures, and supports
checkpointing and restart.

Tolerance to Process Failures
-----------------------------

The features described in this section should be considered
experimental. Which means that they have not been fully tested, and
the behavior may change in future releases. The below notes are some
guidelines on what can be expected in this feature:

 - ERROR RETURNS: Communication failures in MPICH2 are not fatal
   errors. This means that if the user sets the error handler to
   MPI_ERRORS_RETURN, MPICH2 will return an appropriate error code in
   the event of a communication failure. When a process detects a
   failure when communicating with another process, it will consider
   the other process as having failed and will no longer attempt to
   communicate with that process. The user can, however, continue
   making communication calls to other processes. Any outstanding
   send or receive operations to a failed process, or wildcard
   receives (i.e., with MPI_ANY_SOURCE) posted to communicators with a
   failed process, will be immediately completed with an appropriate
   error code.

 - COLLECTIVES: For collective operations performed on communicators
   with a failed process, the collective would return an error on
   some, but not necessarily all processes. A collective call
   returning MPI_SUCCESS on a given process means that the part of the
   collective performed by that process has been successful.

 - PROCESS MANAGER: If used with the hydra process manager, hydra will
   detect failed processes and notify the MPICH2 library. Users can
   query the list of failed processes using the
   MPICH_ATTR_FAILED_PROCESSES predefined attribute on MPI_COMM_WORLD.
   The attribute value is an integer array containing the ranks of the
   failed processes. The array is terminated by MPI_PROC_NULL.

       MPICH2 release specific note: The user needs to declare the
       following extern within the application in order to use the
       attribute (this ideally should be added to mpi.h, but has not
       been done so, to preserve ABI compatibility in the 1.3.x
       release series):

             extern int MPICH_ATTR_FAILED_PROCESSES;

       MPICH2 release specific note: The MPICH_ATTR_FAILED_PROCESSES
       attribute is currently only defined on MPI_COMM_WORLD, but not
       on other communicators.

   Note that hydra by default will abort the entire application when
   any process terminates before calling MPI_Finalize. In order to
   allow an application to continue running despite failed processes,
   you will need to pass the -disable-auto-cleanup option to mpiexec.

 - FAILURE NOTIFICATION: THIS IS AN UNSUPPORTED FEATURE AND WILL
   ALMOST CERTAINLY CHANGE IN THE FUTURE!

   In the current release, hydra notifies the MPICH2 library of failed
   processes by sending a SIGUSR1 signal. The application can catch
   this signal to be notified of failed processes. If the application
   replaces the library's signal handler with its own, the application
   must be sure to call the library's handler from it's own
   handler. Note that you cannot call any MPI function from inside a
   signal handler.

   In future releases, the plan is to provide a call such as
   MPIX_Failure_notify that will allow the user to register a callback
   function that will be called on process failures. This mechanism
   has not been added yet to preserve ABI compatibility in the 1.3.x
   release series.


Checkpoint and Restart
----------------------

MPICH2 supports checkpointing and restart fault-tolerance using BLCR.

CONFIGURATION

First, you need to have BLCR version 0.8.2 or later installed on your
machine. If it's installed in the default system location, add the
following two options to your configure command:

  --enable-checkpointing
  --with-hydra-ckpointlib=blcr

If BLCR is not installed in the default system location, you'll need
to tell MPICH2's configure where to find it. You might also need to
set the LD_LIBRARY_PATH environment variable so that BLCR's shared
libraries can be found. In this case add the following options to
your configure command:

  --enable-checkpointing
  --with-hydra-ckpointlib=blcr
  --with-blcr=<BLCR_INSTALL_DIR>
  LD_LIBRARY_PATH=<BLCR_INSTALL_DIR>/lib

where <BLCR_INSTALL_DIR> is the directory where BLCR has been
installed (whatever was specified in --prefix when BLCR was
configured).

After it's configured compile as usual (e.g., make; make install).

Note, checkpointing is only supported with the Hydra process manager.


VERIFYING CHECKPOINTING SUPPORT

Make sure MPICH2 is correctly configured with BLCR. You can do this
using:

  mpiexec -info

This should display 'BLCR' under 'Checkpointing libraries available'.


CHECKPOINTING THE APPLICATION

There are two ways to cause the application to checkpoint. You can ask
mpiexec to periodically checkpoint the application using the mpiexec
option -ckpoint-interval (seconds):

  mpiexec -ckpointlib blcr -ckpoint-prefix /tmp/app.ckpoint \
      -ckpoint-interval 3600 -f hosts -n 4 ./app

Alternatively, you can also manually force checkpointing by sending a
SIGUSR1 signal to mpiexec.

The checkpoint/restart parameters can also be controlled with the
environment variables HYDRA_CKPOINTLIB, HYDRA_CKPOINT_PREFIX and
HYDRA_CKPOINT_INTERVAL.

To restart a process:

  mpiexec -ckpointlib blcr -ckpoint-prefix /tmp/app.ckpoint -f hosts -n 4 -ckpoint-num <N>

where <N> is the checkpoint number you want to restart from.

These instructions can also be found on the MPICH2 wiki:

  http://wiki.mcs.anl.gov/mpich2/index.php/Checkpointing

-------------------------------------------------------------------------

8. Environment Variables
========================

MPICH2 provides several environment variables that have different
purposes.

Generic Environment Variables
-----------------------------

  MPICH_NO_LOCAL - Disable shared-memory communication. With this
         option, even communication within a node will use the network
         stack.

               ************************************

  MPICH_PORT_RANGE - Port range to use for MPICH2 internal TCP
         connections. This is useful when some of the host ports are
         blocked by a firewall. For example, setting MPICH_PORT_RANGE
         to "2000:3000" will ensure that MPICH2 will internally only
         uses ports between 2000 and 3000.

               ************************************

  MPICH_ASYNC_PROGRESS - Initiates a spare thread to provide
         asynchronous progress. This improves progress semantics for
         all MPI operations including point-to-point, collective,
         one-sided operations and I/O. Setting this variable would
         increase the thread-safety level to
         MPI_THREAD_MULTIPLE. While this improves the progress
         semantics, it might cause a small amount of performance
         overhead for regular MPI operations.

               ************************************

  MPICH_NAMEPUB_DIR - Allows the user to override where the publish
         and lookup information is placed for connect/accept based
         applications.

-------------------------------------------------------------------------

9. Developer Builds
===================
For MPICH2 developers who want to directly work on the svn, there are
a few additional steps involved (people using the release tarballs do
not have to follow these steps). Details about these steps can be
found here:
http://wiki.mcs.anl.gov/mpich2/index.php/Getting_And_Building_MPICH2

-------------------------------------------------------------------------

10. Installing MPICH2 on Windows
================================

Here are the instructions for setting up MPICH2 on a Windows machine:

(a) Install:
    Microsoft Developer Studio 2003 or later
    Intel Fortran 8.0 or later
    cygwin
choose the dos file format option
install perl and cvs

(b) Checkout mpich2:

    Bring up a command prompt.
    (replace "yourname" with your MCS login name):
    svn co https://svn.mcs.anl.gov/repos/mpi/mpich2/trunk mpich2

(c) Generate *.h.in

    Bring up a cygwin bash shell.
    cd mpich2
    maint/updatefiles
    exit

(d) Execute winconfigure.wsf

(e) Open Developer Studio

    open mpich2\mpich2.sln
    build the ch3sockDebug mpich2 solution
    build the ch3sockDebug mpich2s project
    build the ch3sockRelease mpich2 solution
    build the ch3sockRelease mpich2s project
    build the Debug mpich2 solution
    build the Release mpich2 solution
    build the fortDebug mpich2 solution
    build the fortRelease mpich2 solution
    build the gfortDebug mpich2 solution
    build the gfortRelease mpich2 solution
    build the sfortDebug mpich2 solution
    build the sfortRelease mpich2 solution

(f) Open a command prompt

    cd to mpich2\maint
    execute "makegcclibs.bat"

(g) Open another Developer Studio instance

    open mpich2\examples\examples.sln
    build the Release target of the cpi project

(h) Return to Developer Studio with the mpich2 solution

    set the version numbers in the Installer project
    build the Installer mpich2 solution

(i) Test and distribute mpich2\maint\ReleaseMSI\mpich2.msi

    mpich2.msi can be renamed, eg mpich2-1.1.msi

(j) To install the launcher:

    Copy smpd.exe to a local directory on all the nodes.
    Log on to each node as an administrator and execute "smpd.exe -install"

(k) Compile and run an MPI application:

    Compile an mpi application. Use mpi.h from mpich2\src\include\win32
    and mpi.lib in mpich2\lib
    
    Place your executable along with the mpich2 dlls somewhere accessable
    to all the machines.
    
    Execute a job by running something like: mpiexec -n 3 myapp.exe

-------------------------------------------------------------------------

11. Multiple Fortran compiler support
=====================================

If the C compiler that is used to build MPICH2 libraries supports both
multiple weak symbols and multiple aliases of common symbols, the
Fortran 77 binding can support multiple Fortran compilers. The
multiple weak symbols support allow MPICH2 to provide different name
mangling scheme (of subroutine names) required by differen Fortran
compilers. The multiple aliases of common symbols support enables
MPICH2 to equal different common block symbols of the MPI Fortran
constant, e.g. MPI_IN_PLACE, MPI_STATUS_IGNORE. So they are understood
by different Fortran compilers.

Since the support of multiple aliases of common symbols is
new/experimental, users can disable the feature by using configure
option --disable-multi-aliases if it causes any undesirable effect,
e.g. linker warnings of different sizes of common symbols, MPIFCMB*
(the warning should be harmless).

We have only tested this support on a limited set of
platforms/compilers. On linux, if the C compiler that builds MPICH2
is either gcc or icc, the above support will be enabled by configure.
At the time of this writing, pgcc does not seem to have this multiple
aliases of common symbols, so configure will detect the deficiency and
disable the feature automatically. The tested Fortran compiler
includes GNU Forran compilers(gfortan, g77), Intel Fortran
compiler(ifort), Portland Group Fortran compilers(pgf77, pgf90),
Absoft Fortran compilers (af77, af90), and IBM XL fortran
compiler(xlf). What this mean is that if mpich2 is built by
gcc/gfortran, the resulting mpich2 library can be used to link a
Fortran program compiled/linked by another fortran compiler, say
pgf77, say through mpif77 -f77=pgf77. As long as the Fortran program
is linked without any errors by one of these compilers, the program
shall be running fine.