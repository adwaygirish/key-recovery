package shamir

import (
	"fmt"
	"key_recovery/modules/files"
	"key_recovery/modules/finite"
	"log"
)

func GetTablesGF8() {
	limit := uint16(283)
	g := finite.GetGenerator8(limit)
	fmt.Println(g)
	gs := finite.GetAllGenerators8(limit)
	fmt.Println(gs)
	expTable := finite.GenerateExpTable8(g, limit)
	fmt.Println(expTable)
	fmt.Println(len(expTable))
	logTable := finite.GenerateLogTable8(g, limit)
	fmt.Println(logTable)
	fmt.Println(len(logTable))

	for i := 1; i < 256; i++ {
		logV := logTable[i]
		expV := expTable[logV]
		if expV != uint8(i) {
			fmt.Printf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}

	fmt.Println("Check done for 8")

	expTableName := "expTable_8.gob"
	logTableName := "logTable_8.gob"
	err := files.SaveSlice8ToFile(expTableName, expTable)
	if err != nil {
		log.Fatalln(err)
	}
	err = files.SaveSlice8ToFile(logTableName, logTable)
	if err != nil {
		log.Fatalln(err)
	}

	readExpTable16, err := files.LoadSlice8FromFile(expTableName)
	if err != nil {
		log.Fatalln(err)
	}
	readLogTable16, err := files.LoadSlice8FromFile(logTableName)
	if err != nil {
		log.Fatalln(err)
	}

	for i := 1; i < 65536; i++ {
		logV := readLogTable16[i]
		expV := readExpTable16[logV]
		if expV != uint8(i) {
			fmt.Printf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}
}

func GetTablesGF32() {
	limit16 := uint32(69643)
	g16 := finite.GetGenerator16(limit16)
	fmt.Println(g16)
	// gs16 := finite.GetAllGenerators16(limit16)
	// fmt.Println(gs16)
	expTable16 := finite.GenerateExpTable16(g16, limit16)
	logTable16 := finite.GenerateLogTable16(g16, limit16)

	for i := 1; i < 65536; i++ {
		logV := logTable16[i]
		expV := expTable16[logV]
		if expV != uint16(i) {
			fmt.Printf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}
	fmt.Println("Check done for 16")
	expTableName16 := "expTable_16.gob"
	logTableName16 := "logTable_16.gob"
	err := files.SaveSlice16ToFile(expTableName16, expTable16)
	if err != nil {
		log.Fatalln(err)
	}
	err = files.SaveSlice16ToFile(logTableName16, logTable16)
	if err != nil {
		log.Fatalln(err)
	}

	readExpTable16, err := files.LoadSlice16FromFile(expTableName16)
	if err != nil {
		log.Fatalln(err)
	}
	readLogTable16, err := files.LoadSlice16FromFile(logTableName16)
	if err != nil {
		log.Fatalln(err)
	}

	for i := 1; i < 65536; i++ {
		logV := readLogTable16[i]
		expV := readExpTable16[logV]
		if expV != uint16(i) {
			fmt.Printf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}
}
