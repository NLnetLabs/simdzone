.. include:: links.rst

####################
Building the sources
####################

.. toctree::
   :maxdepth: 1
   :hidden:

|project| supports a wide variety of platforms and architectures by design.
The library performs well on any processor, but a modern processor supporting
single instruction, multiple data (SIMD) is required for best performance.

Supported instruction sets.

 * AVX2
 * SSE4.2

.. note::
   Support for additional SIMD instruction sets like Arm Neon, AVX-512, etc
   will be implemented, but is somewhat hindered by lack of available hardware.
   Help with implementing or even testing support for non-x86_64 architectures
   is greatly appreciated.


Automated builds are in place for Linux, macOS and Windows. Any operating
system specific issues for those platforms are caught early, but |project|
strives to work on many operating systems.


Prerequisites
=============

.. note::
    |project| started out as a replacement zone parser for NSD and is included
    in the NSD source packages and repository. For compatibility with the
    build system used by NSD, an autoconf configure script and a Makefile are
    included, but for standalone compilation, CMake is required.

|project| is implemented in C and a C compiler supporting C99 is required to
build the libary. e.g. GCC, Clang or Microsoft Visual Studio (MSVC). The
project purposely has no runtime dependencies.

Make sure the following software is installed on your system:

 * A C99 compatible C compiler.
 * |url::git| version control system.
 * |url::cmake|, version 3.10 or later, see :ref:build_options.
 * Optionally, |url::cmocka| when building with testing.
 * Optionally, |url::doxygen| when building with documentation.
 * Optionally, |url::sphinx| when building with documentation.


.. note::
    |url::conan| can be used to manage build dependencies.


.. tabs::

    .. group-tab:: Linux

      Install dependencies.

      .. code-block:: console

            dnf install git cmake gcc
            apt install git cmake gcc

    .. group-tab:: macOS

        Install XCode from the App Store.

    .. group-tab:: Windows

      Install Microsoft Visual Studio, then install |url::chocolatey|.

      .. code-block:: console

            choco install git
            choco install cmake


Building
========

Clone |project| from GitHub:

.. code-block:: console

    git clone https://github.com/NLnetLabs/simdzone.git
    cd simdzone

Build the library using the operating system specific instructions below. The
instructions are tailored to users of the library. Developers may want to
choose a different build type, e.g. ``RelWithDebInfo`` or ``Debug``, and
skip installation.

.. tabs::

    .. group-tab:: Linux

        .. code-block:: console

            mkdir build
            cd build
            cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=<install-location> ..
            cmake --build . --parallel
            cmake --install .

    .. group-tab:: macOS

        .. code-block:: console

            mkdir build
            cd build
            cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=<install-location> ..
            cmake --build . --parallel
            cmake --install .

    .. group-tab:: Windows

        .. code-block:: console

            mkdir build
            cd build
            cmake -G "<generator>" -A <architecture> -DCMAKE_INSTALL_PREFIX=<install-location> ..
            cmake --build . --parallel --config Release
            cmake --install . --config Release

        |project| can be built using for any of the supported platforms.
        Omitting ``-G "<generator>" -A <architecture>`` usually selects a
        sensible default (that of the host). Different platforms and toolkits
        can be selected though. See the manual page ``man cmake-generators``
        or the `cmake generators documentation
        <https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html>`_
        for details.

Build options
-------------

.. list-table::

   * - ``-DBUILD_TESTING=ON``
     - Build the testing tree.
   * - ``-DBUILD_DOCUMENTATION=ON``
     - Build documentation.
