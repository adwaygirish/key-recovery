package files

import (
	"encoding/csv"
	"encoding/gob"
	"key_recovery/modules/utils"
	"os"
	"strconv"
	"strings"
)

// Function for creating a directory if it does not exist
func CreateDirectory(path string) (error, bool) {
	// Check if the directory exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Directory does not exist, so create it
		err := os.MkdirAll(path, os.ModeDir|os.ModePerm)
		if err != nil {
			return err, false
		}
	} else if err != nil {
		// An error occurred while checking the directory
		return err, false
	} else {
		// Directory already exists
		return nil, false
	}
	// Directory created successfully
	return nil, true
}

func CreateFile(filename string) (error, bool) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// Directory does not exist, so create it
		file, err := os.Create(filename)
		if err != nil {
			return err, false
		}
		defer file.Close()
	} else if err != nil {
		// An error occurred while checking the directory
		return err, false
	} else {
		// Directory already exists
		return nil, false
	}
	// Directory created successfully
	return nil, true
}

// Create a csv file for storing the simulation results
func CreateCSVResultsFile(csvDir string) (string, error) {
	csvFilename := csvDir + "results-0.csv"
	dotLocation := strings.IndexRune(csvFilename, '.')
	for {
		err, flag := CreateFile(csvFilename)
		if err != nil {
			return "", err
		} else {
			if flag {
				break
			} else {
				// Increment the directory number
				// fmt.Println(csvFilename[len(csvDir)+8 : dotLocation])
				dotLocation = strings.IndexRune(csvFilename, '.')
				dirNumber, err := strconv.Atoi(csvFilename[len(csvDir)+8 : dotLocation])
				// fmt.Println(dirNumber)
				if err != nil {
					return "", err
				}
				csvFilename = csvDir + "results-" + strconv.Itoa(dirNumber+1) + ".csv"
			}
		}
	}
	return csvFilename, nil
}

// Generate CSV results directories
func CreateCSVResultsDirectory(csvDir string) (string, error) {
	csvResultsDirName := csvDir + "results-0"
	for {
		err, flag := CreateDirectory(csvResultsDirName)
		if err != nil {
			return "", err
		} else {
			// If the directory is created
			if flag {
				break
			} else { // If the directory is not created
				// Increase the directory number
				dirNumber, err := strconv.Atoi(csvResultsDirName[len(csvDir)+8:])
				if err != nil {
					return "", err
				}
				csvResultsDirName = csvDir + "results-" + strconv.Itoa(dirNumber+1)
			}
		}
	}
	csvResultsDirName = csvResultsDirName + "/"
	return csvResultsDirName, nil
}

// This is for writing the results to a csv file
func WriteToCSVFile(csvFilename string, data [][]interface{}) error {
	file, err := os.OpenFile(csvFilename, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	// Write data to the CSV file
	for _, row := range data {
		stringRow := make([]string, len(row))
		for i, v := range row {
			stringRow[i] = utils.ConvertToString(v)
		}
		if err := writer.Write(stringRow); err != nil {
			return err
		}
	}
	return nil
}

func SaveSlice16ToFile(filename string, data []uint16) error {
	// Create or open the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a new encoder and encode the slice
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(data)
	if err != nil {
		return err
	}

	return nil
}

func LoadSlice16FromFile(filename string) ([]uint16, error) {
	var data []uint16

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a new decoder and decode the data into the slice
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func SaveSlice8ToFile(filename string, data []uint8) error {
	// Create or open the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a new encoder and encode the slice
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(data)
	if err != nil {
		return err
	}

	return nil
}

func LoadSlice8FromFile(filename string) ([]uint8, error) {
	var data []uint8

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a new decoder and decode the data into the slice
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
