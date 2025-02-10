# What's this ?

This is a little tool I wrote in golang to scan single files, directories, JAR, WAR and ZIP archives for Java .class
files, determine the JDK version they require (and whether the class uses JDK preview features) as well as optionally
enforce minimum/maximum constraints that must be met by all .class file.

![<img src="screenshot.png">](https://github.com/toby1984/classfilescanner/screenshot.png)

# Building

I've used golang 1.23. Simply run "go build" and you're good to go.

# Usage

You can get help by running `classfilescanner -h`

    Scans individual .class files, directories, JAR/WAR/ZIP files for the Java class file versions.
    Optionally fails with an error when files that are not compatible with the given version constraint(s) are encountered
    JDK versions need to be a single number ( 8 = JDK 8, 11 = JDK 1, etc)

    Usage: [-v|--verbose] [q|--quiet] [-p|--preview-is-ok] [-m|--minimum-jdk <JDK number, inclusive>] [-M|--maximum-jdk <JDK number, inclusive>]  [-h|--help] file1 <file2 <...>>

