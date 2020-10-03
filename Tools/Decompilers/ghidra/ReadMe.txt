To install Ghidra, simply extract the Ghidra distribution file to the desired filesystem destination using any unzip program (built-in OS utilities, 7-Zip, WinZip, WinRAR, etc)
Installation Notes

    Ghidra does not use a traditional installer program. Instead, the Ghidra distribution file is simply extracted in-place on the filesystem. This approach has advantages and disadvantages. On the up side, administrative privilege is not required to install Ghidra for personal use. Also, because installing Ghidra does not update any OS configurations such as the registry on Windows, removing Ghidra is as simple as deleting the Ghidra installation directory. On the down side, Ghidra will not automatically create a shortcut on the desktop or appear in application start menus.
    Administrative privilege may be required to extract Ghidra to certain filesystem destinations (such as C:\), as well as install the Ghidra Server as a service.
    Ghidra relies on using directories outside of its installation directory to manage both temporary and longer-living cache files. Ghidra attempts to use standard OS directories that are designed for these purposes in order to avoid several issues, such as storing large amounts of data to a roaming profile. If it is suspected that the default location of these directories is causing a problem, they can be changed by modifying the relevant properties in the support/launch.properties file.

Java Notes

    Ghidra requires a supported version of a Java Runtime and Development Kit on the PATH to run. However, if there is a version of Java on the PATH that Ghidra does not support, it will use that version of Java (if 1.7 or later) to assist in locating a supported version on your system. If one cannot be automatically located, the user will be prompted to enter a path to the Java home directory to use (the Java home directory is the parent directory of Java's bin directory). This minimizes the impact Ghidra has on pre-existing configurations of Java that other software may rely on.
    If Ghidra failed to run because no versions of Java were on the PATH, a supported JDK should be manually installed and added to the PATH. The following steps outline how to add a JDK distribution to the operating system's PATH.

        Windows: Extract the JDK distribution (.zip file) to your desired location and add the JDK's bin directory to your PATH:

            Extract the JDK:
                Right-click on the zip file and click Extract All...
                Click Extract

            Open Environment Variables window:

                Windows 10: Right-click on Windows start button, and click System

                Windows 7: Click Windows start button, right-click on Computer, and click Properties
                Click Advanced system settings
                Click Environment variables...

            Add the JDK bin directory to the PATH variable:
                Under System variables, highlight Path and click Edit...
                At the end of the the Variable value field, add a semicolon followed by <path of extracted JDK dir>\bin
                Click OK
                Click OK
                Click OK
            Restart any open Command Prompt windows for changes to take effect

        Linux and macOS (OS X): Extract the JDK distribution (.tar.gz file) to your desired location, and add the JDK's bin directory to your PATH:
            Extract the JDK:

                tar xvf <JDK distribution .tar.gz>

            Open ~/.bashrc with an editor of your choice. For example:

                vi ~/.bashrc

            At the very end of the file, add the JDK bin directory to the PATH variable:

                export PATH=<path of extracted JDK dir>/bin:$PATH

            Save file
            Restart any open terminal windows for changes to take effect
    In some cases, you may want Ghidra to launch with a specific version of Java instead of the version that Ghidra automatically locates. To force Ghidra to launch with a specific version of Java, set the JAVA_HOME_OVERRIDE property in the support/launch.properties file. If this property is set to an incompatible version of Java, Ghidra will revert to automatically locating a compatible version. Note that some Java must still be on the PATH in order for Ghidra to use the JAVA_HOME_OVERRIDE property. This limitation will be addressed in a future version of Ghidra.
