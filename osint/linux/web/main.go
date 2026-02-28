package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"slices"

	"github.com/alexflint/go-arg"
	"github.com/apokalyptik/phpass"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

type args struct {
	InputFile  string `arg:"-i,--input" help:"Path to input file. If not specified, stdin is used"`
	OutputFile string `arg:"-o,--output" help:"Path to output file. If not specified, stdout is used. Cannot be the same as the input file"`
	DryRun     bool   `arg:"-d,--dry-run" default:"false" help:"Shows which hashes would have been replaced without doing anything"`
	Password   string `arg:"-p,--password,required" help:"The password to use when replacing hashes"`

	BufferSize int `arg:"-b,--buffer-size" default:"8192" help:"Specifies the size of buffer used to read values in"`
}

func main() {
	var args args
	arg.MustParse(&args)

	// Open input file
	var input_reader io.Reader
	if args.InputFile != "" {
		ifile, err := os.Open(args.InputFile)
		if err != nil {
			log.Fatalln("Error opening input file:", err)
		}
		defer ifile.Close()
		input_reader = ifile
	} else {
		input_reader = os.Stdin
	}

	// Open output file
	var output_writer io.Writer
	if args.DryRun {
		output_writer = io.Discard
	} else if args.OutputFile != "" {
		ofile, err := os.Create(args.OutputFile)
		if err != nil {
			log.Fatalln("Error opening output file:", err)
		}
		defer ofile.Close()
		output_writer = ofile
	}

	// Define regex patterns for various hash types and count map for replacements
	hashPatterns := map[string]string{
		"MD5":               `'[a-fA-F0-9]{32}'`,
		"SHA1":              `'[a-fA-F0-9]{40}'`,
		"SHA256":            `'[a-fA-F0-9]{64}'`,
		"PHPMD5":            `'\$P\$[0-9a-zA-Z.\/]{31}'`,
		"SHA512":            `'[a-fA-F0-9]{128}'`,
		"DES":               `'[a-z0-9\/.]{12}[.26AEIMQUYcgkosw]{1}'`,
		"HALFMD5":           `'[a-f0-9]{16}'`,
		"PRESTASHOP":        `'[a-f0-9]{32}:[a-z0-9]{56}'`,
		"MD2":               `'(\$md2\$)?[a-f0-9]{32}$'`,
		"MD5CRYPT":          `'\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?'`,
		"PHPBB":             `'\$H\$[a-z0-9\/.]{31}'`,
		"PALSHOP":           `'[a-f0-9]{51}'`,
		"BCRYPT":            `'(\$2[abxy]?|\$2)\$[0-9]{2}\$[a-zA-Z0-9\/.]{53}'`,
		"YESCRYPT":          `'\$y\$[.\/A-Za-z0-9]+\$[.\/a-zA-Z0-9]+\$[.\/A-Za-z0-9]{43}'`,
		"JOOMLA":            `'[a-f0-9]{32}:[a-z0-9]{32}'`,
		"PBKDF-HMAC-SHA512": `'\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}'`,
		"DJANGO":            `'sha256\$[a-z0-9]+\$[a-f0-9]{64}'`,
		"MEDIAWIKI":         `'[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}'`,
		"Hmailserver":       `'[a-f0-9]{70}'`,
		"PHPS":              `'\$PHPS\$.+\$[a-f0-9]{32}'`,
	}

	// Map to store replacement counts for each hash type
	replacementCounts := make(map[string]int)

	// Compile the regular expression patterns
	hashRegexes := make(map[string]*regexp.Regexp)
	for hashType, pattern := range hashPatterns {
		r := regexp.MustCompile(pattern)
		hashRegexes[hashType] = r
	}

	// Buffer
	half_buffer_size := args.BufferSize / 2
	buffer := make([]byte, half_buffer_size*2) // This weird multiplication ensures the buffer isn't oddly sized
	back_half := 0
	front_half := 0
	for {
		var err error
		front_half, err = input_reader.Read(buffer[back_half : back_half+half_buffer_size])
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalln("Error reading to input:", err)
		}

		buffer = buffer[:front_half+back_half]

		// Check for matches with each hash type
		for hashType, regex := range hashRegexes {
			matches := regex.FindAll(buffer, -1)
			if len(matches) > 0 {
				// Increment the replacement count for this hash type
				replacementCounts[hashType] += len(matches)

				switch hashType {
				case "MD5":
					// Replace each MD5 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						hasher := md5.New()
						hasher.Write([]byte(args.Password))
						newHash := "'" + hex.EncodeToString(hasher.Sum(nil)) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHash))
					}
				case "SHA1":
					// Replace each SHA1 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						hasher := sha1.New()
						hasher.Write([]byte(args.Password))
						newHash := "'" + hex.EncodeToString(hasher.Sum(nil)) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHash))
					}
				case "SHA256":
					// Replace each SHA256 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						hasher := sha256.New()
						hasher.Write([]byte(args.Password))
						newHash := "'" + hex.EncodeToString(hasher.Sum(nil)) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHash))
					}
				case "SHA512":
					// Replace each SHA512 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						hasher := sha512.New()
						hasher.Write([]byte(args.Password))
						newHash := "'" + hex.EncodeToString(hasher.Sum(nil)) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHash))
					}
				case "PHPMD5":
					// Replace each PHPMD5 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						hasher := phpass.New(nil)
						newHash, err := hasher.Hash([]byte(args.Password))
						if err != nil {
							fmt.Println("Error hashing password with PHPMD5:", err)
							return
						}
						newHashStr := "'" + string(newHash) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHashStr))
					}
				case "BCRYPT":
					// Replace each BCRYPT hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						bytes, err := bcrypt.GenerateFromPassword([]byte(args.Password), 14)
						if err != nil {
							fmt.Println("Error hashing password with BCRYPT:", err)
							return
						}
						newHashStr := "'" + string(bytes) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHashStr))
					}
				case "PBKDF-HMAC-SHA512":
					// Replace each PBKDF-HMAC-SHA512 hash with a new hash of the provided password
					for _, match := range matches {
						fmt.Println(match)
						salt := "TechicallyWereBetter"
						newHash := pbkdf2.Key([]byte(args.Password), []byte(salt), 4096, 64, sha512.New)
						newHashStr := "'" + hex.EncodeToString(newHash) + "'"
						buffer = regex.ReplaceAll(buffer, []byte(newHashStr))
					}
				}
			}
		}
		_, err = output_writer.Write(buffer[:back_half])
		if err != nil {
			log.Fatalln("Error writing to output:", err)
		}

		copy(buffer[:front_half], buffer[back_half:back_half+front_half])
		back_half = front_half
		buffer = slices.Grow(buffer, 2*half_buffer_size)
	}

	_, err := output_writer.Write(buffer[:back_half])
	if err != nil {
		log.Fatalln("Error writing to output:", err)
	}

	for hashType, count := range replacementCounts {
		fmt.Printf("%s hashes replaced: %d\n", hashType, count)
	}
}