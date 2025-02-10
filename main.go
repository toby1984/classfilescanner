package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const VERSION = "1.0"

// TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>
var debug = false
var quiet = false

var checkConstraints = false
var previewOk = false

var multiVersionRegEx = regexp.MustCompile(`META-INF/versions/(?P<Version>\d+)/.*`)

const NOT_SET uint32 = 0xffffffff

// classfile required maximum version, uint32 composed out of uint16(major) << 16 | uint16(minor)
var maximumJdkVersion uint32 = NOT_SET
var maximumClassFileVersion = NOT_SET // FIXME: Rename to maximumClassFileVersion

// classfile required minimum version, uint32 composed out of uint16(major) << 16 | uint16(minor)
var minimumJdkVersion uint32 = NOT_SET
var minimumClassFileVersion = NOT_SET // FIXME: Rename to minimumClassFileVersion

// mapping from <major>.<minor> version to JDK version string
var classVersionMapping = getClassFileVersionMapping()

func getClassFileVersionMapping() map[uint32]string {
	var classFileVersionToJdk = make(map[uint32]string)

	classFileVersionToJdk[uint32(45<<16)] = "1.0"
	classFileVersionToJdk[uint32((45<<16)|3)] = "1.1"
	classFileVersionToJdk[uint32(46<<16)] = "1.2"
	classFileVersionToJdk[uint32(47<<16)] = "1.3"
	classFileVersionToJdk[uint32(48<<16)] = "1.4"
	classFileVersionToJdk[uint32(49<<16)] = "5"
	classFileVersionToJdk[uint32(50<<16)] = "6"
	classFileVersionToJdk[uint32(51<<16)] = "7"
	classFileVersionToJdk[uint32(52<<16)] = "8"
	classFileVersionToJdk[uint32(53<<16)] = "9"
	classFileVersionToJdk[uint32(54<<16)] = "10"
	classFileVersionToJdk[uint32(55<<16)] = "11"
	classFileVersionToJdk[uint32(56<<16)] = "12"
	classFileVersionToJdk[uint32(57<<16)] = "13"
	classFileVersionToJdk[uint32(58<<16)] = "14"
	classFileVersionToJdk[uint32(59<<16)] = "15"
	classFileVersionToJdk[uint32(60<<16)] = "16"
	classFileVersionToJdk[uint32(61<<16)] = "17"
	classFileVersionToJdk[uint32(62<<16)] = "18"
	classFileVersionToJdk[uint32(63<<16)] = "19"
	classFileVersionToJdk[uint32(64<<16)] = "20"
	classFileVersionToJdk[uint32(65<<16)] = "21"
	classFileVersionToJdk[uint32(66<<16)] = "22"
	classFileVersionToJdk[uint32(67<<16)] = "23"
	classFileVersionToJdk[uint32(68<<16)] = "24"
	classFileVersionToJdk[uint32(69<<16)] = "25"

	return classFileVersionToJdk
}

func logDebug(format string, args ...interface{}) {
	if debug {
		println(fmt.Sprintf(format, args...))
	}
}

func logVerbose(format string, args ...interface{}) {
	if !quiet || debug {
		println(fmt.Sprintf(format, args...))
	}
}

func readFromZipFileEntry(archiveEntry *zip.File, bytesToRead int) ([]byte, error) {

	buffer := make([]byte, 0)
	file, err := archiveEntry.Open()
	if err != nil {
		log.Fatal("Failed to open archive entry for ", archiveEntry.Name)
	}

	tmpBuffer := make([]byte, 32768)
	bytesRemaining := bytesToRead
	for bytesRemaining > 0 {
		actualBytesRead, err := file.Read(tmpBuffer)
		if err != nil && err != io.EOF {
			log.Fatalf("Error while reading from archive entry %s (%s)", archiveEntry.Name, err.Error())
			return nil, err
		}
		if actualBytesRead < 1 {
			log.Fatalf("Still trying to read %d more bytes from entry %s but got only %d", bytesRemaining, archiveEntry.Name, actualBytesRead)
			return nil, err
		}
		var bytesToCopy int
		if bytesRemaining < actualBytesRead {
			bytesToCopy = bytesRemaining
		} else {
			bytesToCopy = actualBytesRead
		}
		buffer = append(buffer, tmpBuffer[:bytesToCopy]...)
		bytesRemaining -= actualBytesRead
	}

	file.Close()
	return buffer, nil
}

func processClassFileZipEntry(classFileEntry *zip.File) {

	fileSize := classFileEntry.FileHeader.UncompressedSize64
	if fileSize < 26 {
		logDebug("%s is too small to be a valid .class file", classFileEntry.Name)
		return
	}

	logDebug("%7d bytes, %s", fileSize, classFileEntry.Name)

	desiredLen := math.Min(1024, float64(fileSize))
	buffer, err := readFromZipFileEntry(classFileEntry, int(desiredLen))
	if err != nil {
		log.Fatal("Failed to uncompress entry for ", classFileEntry.Name)
	}
	processClassFileData(buffer, classFileEntry.Name)
}

func processClassFileData(buffer []byte, fileName string) {

	/*
		ClassFile {
		    u4             magic; // 0xCAFEBABE
		    u2             minor_version;
		    u2             major_version;
	*/
	magic := binary.BigEndian.Uint32(buffer[0:4])
	if magic != 0xcafebabe {
		log.Fatal("Encountered .class file with invalid MAGIC %x", magic)
	}
	majorVersion := binary.BigEndian.Uint16(buffer[6:8])
	minorVersion := binary.BigEndian.Uint16(buffer[4:6])

	/* See JEP-12
	 * A class file denotes that it depends on the preview features of Java SE $N by having a major_version item that
	 * corresponds to Java SE $N and a minor_version item that has all 16 bits set.
	 * For example, a class file that depends on the preview features of Java SE 17 would have version 61.65535.
	 */
	key := uint32(majorVersion)<<16 | uint32(minorVersion)&0xffff
	jdk, found := classVersionMapping[key]
	if !found {
		jdk = "<unknown JDK>"
	}
	usesPreviewFeatures := minorVersion == 0xffff
	if usesPreviewFeatures {
		jdk += " (PREVIEW)"
	}
	if !checkConstraints && !quiet {
		println(fmt.Sprintf("%s requires Java %s (classfile version %d.%d)", fileName, jdk, majorVersion, minorVersion))
	}

	if checkConstraints {
		var isInvalid = false
		if maximumClassFileVersion != NOT_SET {
			var maxMajor = uint16(maximumClassFileVersion >> 16)
			if majorVersion > maxMajor {
				isInvalid = true
				println("ERROR - Maximum JDK requirement violated.")
			}
		}
		if minimumClassFileVersion != NOT_SET {
			var minMajor = uint16(minimumClassFileVersion >> 16)
			if majorVersion < minMajor {
				isInvalid = true
				println("ERROR - Minimum JDK requirement violated.")
			}
		}
		if usesPreviewFeatures && !previewOk {
			isInvalid = true
			println("ERROR - Usage of preview features is not permitted.")
		}
		if isInvalid {
			println(fmt.Sprintf("Offending file %s requires Java %s (classfile version %d.%d)", fileName, jdk, majorVersion, minorVersion))
			os.Exit(2)
		}
	}
}

func processZipArchiveFromBytes(zipArchiveBytes []byte) {

	ioReader := bytes.NewReader(zipArchiveBytes)
	validVersions := scanForValidVersionsInMultiReleaseJAR(ioReader, int64(len(zipArchiveBytes)))

	reader, err := zip.NewReader(ioReader, int64(len(zipArchiveBytes)))
	if err != nil {
		log.Fatal("Failed to create uncompress byte array")
	}

	for _, file := range reader.File {
		processEntryInZipFile(file, validVersions)
	}
}

func scanForValidVersionsInMultiReleaseJAR(input io.ReaderAt, numBytesToRead int64) map[int]bool {
	validVersions := make(map[int]bool)

	reader, err := zip.NewReader(input, numBytesToRead)
	if err != nil {
		log.Fatalf("Error while trying to scan for multi-release JAR versions: %s", err.Error())
	}

	isMultiReleaseJar := false
	for _, file := range reader.File {
		v := extractMultiVersion(file.Name)
		if v != nil {
			isMultiReleaseJar = true

			if minimumJdkVersion != NOT_SET && uint32(*v) < minimumJdkVersion {
				continue
			}
			if maximumJdkVersion != NOT_SET && uint32(*v) > maximumJdkVersion {
				continue
			}
			validVersions[*v] = true
		}
	}
	if isMultiReleaseJar {
		if len(validVersions) > 0 {
			keys := make([]int, 0, len(validVersions))
			for input := range maps.Keys(validVersions) {
				keys = append(keys, input)
			}
			logVerbose("Multi-release JAR contains classfiles for the following JDK versions that are compatible with the requested constraints: %v", keys)
			return validVersions
		} else {
			logVerbose("None of the available JDK versions in this multi-release JAR match the requested constraints.")
		}
	}
	return nil
}

func getVersionsToCheck(ioReader io.Reader) (map[int]bool, error) {
	var versionsToCheck map[int]bool = nil
	if minimumClassFileVersion != NOT_SET || maximumClassFileVersion != NOT_SET || !previewOk {

		data, err := io.ReadAll(ioReader)
		if err != nil {
			return nil, err
		}
		foundVersions := scanForValidVersionsInMultiReleaseJAR(bytes.NewReader(data), int64(len(data)))

		versionsToCheck = make(map[int]bool)
		for key, _ := range foundVersions {
			if (minimumClassFileVersion != NOT_SET && uint32(key) >= minimumJdkVersion) || (maximumClassFileVersion != NOT_SET && uint32(key) <= maximumJdkVersion) {
				versionsToCheck[key] = true
			}
		}
		if len(versionsToCheck) == 0 {
			versionsToCheck = nil
		}
	}
	return versionsToCheck, nil
}

func processZipArchiveFromFile(fileName string) {

	// check if we're processing a multi-release JAR
	// and make sure we only scan the versions that are compatible with
	// our search constraint.
	// if none of the available versions are compatible with our constraints,
	// all files will be scanned , tripping a failure.
	var versionsToCheck map[int]bool = nil
	if minimumClassFileVersion != NOT_SET || maximumClassFileVersion != NOT_SET || !previewOk {

		ioReader, err := os.Open(fileName)
		defer ioReader.Close()

		versionsToCheck, err = getVersionsToCheck(ioReader)
		if err != nil {
			log.Fatal("Failed to open file ", fileName, err.Error())
		}
		ioReader.Close()
	}

	// do the actual file parsing
	archive, err := zip.OpenReader(fileName)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range archive.File {
		if file.FileHeader.FileInfo().IsDir() {
			logDebug("Skipping directory %s", file.Name)
		} else {
			processEntryInZipFile(file, versionsToCheck)
		}
	}
}

func extractMultiVersion(input string) *int {

	matches := multiVersionRegEx.FindAllStringSubmatch(input, -1)
	if matches != nil {
		for _, match := range matches {
			version, err := strconv.Atoi(match[multiVersionRegEx.SubexpIndex("Version")])
			if err != nil {
				log.Fatal("Unreachable code reached")
			}
			return &version
		}
	}
	return nil
}

func processEntryInZipFile(zipEntry *zip.File, versionsToCheck map[int]bool) {

	if zipEntry.FileHeader.FileInfo().IsDir() {
		logDebug("Skipping directory %s", zipEntry.Name)
		return
	}
	if versionsToCheck != nil {
		versionFromFolderName := extractMultiVersion(zipEntry.Name)
		if versionFromFolderName != nil && !versionsToCheck[*versionFromFolderName] {
			logDebug("Ignoring file %s from multi-release version %d", zipEntry.Name, *versionFromFolderName)
			return
		}
	}

	if strings.HasSuffix(zipEntry.Name, ".class") {
		processClassFileZipEntry(zipEntry)
	} else if isZipArchive(zipEntry.Name) {
		fileSize := zipEntry.FileHeader.UncompressedSize64
		logVerbose(fmt.Sprintf("Inspecting nested archive %s", zipEntry.Name))
		allBytes, err := readFromZipFileEntry(zipEntry, int(fileSize))
		if err != nil {
			log.Fatal("Failed to uncompress ", zipEntry.Name)
		}
		processZipArchiveFromBytes(allBytes)
	} else {
		logDebug("IGNORED: file name '%s' does not end with .class", zipEntry.Name)
	}
}

func jdkVersionToMajor(version string) uint32 {
	parts := strings.Split(version, ".")
	if len(parts) < 1 || len(parts) > 2 {
		log.Fatal("Invalid JDK version string syntax: " + version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatal("Invalid JDK version string syntax: " + version)
	}
	return uint32(major)
}

func jdkVersionToMajorMinor(version string) uint32 {

	for key, value := range classVersionMapping {
		if version == value {
			return key
		}
	}
	log.Fatalf("Unsupported JDK version number: %s", version)
	// never reached
	return 0
}

func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		log.Fatal("Invalid command line. Need at least one file to scan")
	}

	fileNames := make([]string, 0)
	var idx = 0
	printHelp := false
	for idx < len(argsWithoutProg) {
		arg := argsWithoutProg[idx]
		idx++
		if arg == "-h" || arg == "--help" {
			printHelp = true
			break
		} else if arg == "-p" || arg == "--preview-is-ok" {
			previewOk = true
			checkConstraints = true
		} else if arg == "-d" || arg == "--debug" {
			debug = true
		} else if arg == "-m" || arg == "--minimum-jdk" {
			if idx == len(argsWithoutProg)-1 {
				log.Fatalf("Invalid command line. %s requires an argument", arg)
			}
			checkConstraints = true
			minimumJdkVersion = jdkVersionToMajor(argsWithoutProg[idx])
			minimumClassFileVersion = jdkVersionToMajorMinor(argsWithoutProg[idx])
			idx += 1
		} else if arg == "-M" || arg == "--maximum-jdk" {
			if idx == len(argsWithoutProg)-1 {
				log.Fatalf("Invalid command line. %s requires an argument", arg)
			}
			checkConstraints = true
			maximumJdkVersion = jdkVersionToMajor(argsWithoutProg[idx])
			maximumClassFileVersion = jdkVersionToMajorMinor(argsWithoutProg[idx])
			idx += 1
		} else if arg == "-q" || arg == "--quiet" {
			quiet = true
		} else {
			fileNames = append(fileNames, arg)
		}
	}

	if printHelp {
		fmt.Printf("Version %s\n", VERSION)
		fmt.Printf("Scans individual .class files, directories, JAR/WAR/ZIP files for Java class file versions.\n")
		fmt.Printf("Optionally fails with an exit code 2 when files that are not compatible with given version constraint(s) are encountered\n")
		fmt.Printf("JDK versions need to be a single number ( 8 = JDK 8, 9 = JDK 9, etc)\n")
		fmt.Printf("\nUsage: [-v|--verbose] [q|--quiet] [-p|--preview-is-ok] [-m|--minimum-jdk <JDK number, inclusive>] [-M|--maximum-jdk <JDK number, inclusive>]  [-h|--help] file1 <file2 <...>>\n\n")
		os.Exit(1)
	}

	if debug {
		logVerbose("Debug output enabled.")
	}
	if checkConstraints {
		if minimumClassFileVersion != NOT_SET {
			logVerbose("Will require minimum JDK (inclusive): %s", classVersionMapping[minimumClassFileVersion])
		}
		if maximumClassFileVersion != NOT_SET {
			logVerbose("Will required maximum JDK (inclusive): %s", classVersionMapping[maximumClassFileVersion])
		}
		if previewOk {
			logVerbose("Using preview features is OK.")
		}
	}

	for _, fileName := range fileNames {
		scanFile(fileName)
	}
}

func isDir(fileName string) bool {
	file, err := os.Stat(fileName)
	if err != nil {
		log.Fatalf("Failed to stat() file %s: %s", fileName, err.Error())
	}
	return file.IsDir()
}

func isZipArchive(fileName string) bool {
	return strings.HasSuffix(strings.ToLower(fileName), ".war") ||
		strings.HasSuffix(strings.ToLower(fileName), ".jar") ||
		strings.HasSuffix(strings.ToLower(fileName), ".zip")
}

func scanFile(fileName string) {
	if isDir(fileName) {
		logVerbose("Scanning directory: %s", fileName)
		scanDirectory(fileName)
		return
	}
	if isZipArchive(fileName) {
		logVerbose("Scanning file %s ...", fileName)
		processZipArchiveFromFile(fileName)
	} else if strings.HasSuffix(strings.ToLower(fileName), ".class") {
		logVerbose("Scanning file %s ...", fileName)
		// Scan .class file
		data, err := os.ReadFile(fileName)
		if err != nil {
			log.Fatalf("Failed to open file %s: %s", fileName, err.Error())
		}
		processClassFileData(data, fileName)
	}
}

func scanDirectory(dirName string) {
	entries, err := os.ReadDir(dirName)
	if err != nil {
		log.Fatalf("Failed to read contents of directory %s: %s", dirName, err)
	}
	for _, e := range entries {
		path := filepath.Join(dirName, e.Name())
		scanFile(path)
	}
}
