package main

import (
	"fmt"
	"io"
	"os"
)

func CreateFile(path string) error {
	// detect if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if isError(err) {
			return err
		}
		defer file.Close()
	}

	fmt.Println("==> done creating file", path)
	return nil
}

func WriteFile(path string, data string) error {
	// open file using READ & WRITE permission
	var file, err = os.OpenFile(path, os.O_RDWR, 0644)
	if isError(err) {
		return err
	}
	defer file.Close()

	// write some text line-by-line to file
	_, err = file.WriteString("halo\n")
	if isError(err) {
		return err
	}
	_, err = file.WriteString("mari belajar golang\n")
	if isError(err) {
		return err
	}

	// save changes
	err = file.Sync()
	if isError(err) {
		return err
	}

	fmt.Println("==> done writing to file")
	return nil
}

func ReadFile(path string) (string, error) {
	// re-open file
	var file, err = os.OpenFile(path, os.O_RDWR, 0644)
	if isError(err) {
		return "", err
	}
	defer file.Close()

	// read file, line by line
	var text = make([]byte, 1024)
	for {
		_, err = file.Read(text)

		// break if finally arrived at end of file
		if err == io.EOF {
			break
		}

		// break if error occured
		if err != nil && err != io.EOF {
			isError(err)
			break
		}
	}

	fmt.Println("==> done reading from file")
	return string(text), nil
}

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}

	return (err != nil)
}
