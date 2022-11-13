package main

//package automotivecps

import (
	"encoding/hex"
	"fmt"
	cmap "github.com/orcaman/concurrent-map/v2"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
	"tinygo.org/x/bluetooth"
)

const (
	CONN_HOST = "127.0.0.1"
	CONN_PORT = "5000"
	CONN_TYPE = "tcp"
)

var (
	server                  Server
	Adapter                 = bluetooth.DefaultAdapter
	ANKI_STR_SERVICE_UUID   = bluetooth.NewUUID([16]byte{0xBE, 0x15, 0xBE, 0xEF, 0x61, 0x86, 0x40, 0x7E, 0x83, 0x81, 0x0B, 0xD8, 0x9C, 0x4D, 0x8D, 0xF4})
	ANKI_STR_CHR_READ_UUID  = bluetooth.NewUUID([16]byte{0xBE, 0x15, 0xBE, 0xE0, 0x61, 0x86, 0x40, 0x7E, 0x83, 0x81, 0x0B, 0xD8, 0x9C, 0x4D, 0x8D, 0xF4})
	ANKI_STR_CHR_WRITE_UUID = bluetooth.NewUUID([16]byte{0xBE, 0x15, 0xBE, 0xE1, 0x61, 0x86, 0x40, 0x7E, 0x83, 0x81, 0x0B, 0xD8, 0x9C, 0x4D, 0x8D, 0xF4})
)

type Server struct {
	DiscoveredDevices     cmap.ConcurrentMap[string, AnkiVehicle]
	ConnectedDevices      cmap.ConcurrentMap[string, *bluetooth.Device]
	DeviceCharacteristics cmap.ConcurrentMap[string, []bluetooth.DeviceCharacteristic]
}

type AnkiVehicle struct {
	Address          string
	ManufacturerData string
	LocalName        string
	Addresser        bluetooth.Addresser
}

func main() {
	server.DiscoveredDevices = cmap.New[AnkiVehicle]()
	server.ConnectedDevices = cmap.New[*bluetooth.Device]()
	server.DeviceCharacteristics = cmap.New[[]bluetooth.DeviceCharacteristic]()

	// Listen for connections on host and port
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		log.Fatalln(err)
	}

	// terminate server on port when disconnected
	defer func(l net.Listener) {
		err := l.Close()
		if err != nil {
		}
	}(l)

	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}

// Handles the incoming requests from the tcp connection
func handleRequest(conn net.Conn) {

	// Keep grabbing messages from tcp connection until server termination
	for {
		// Make a buffer to hold incoming data.
		buf := make([]byte, 1024)
		// Read the incoming connection into the buffer.
		_, err := conn.Read(buf)
		if err != nil {
			log.Fatalln("Error reading:", err.Error())
		}

		// Create a goroutine for incoming msg and listen for the next msg
		go func(buf []byte) {
			// parsing msg so the payload can go to the vehicle - payload is at index [1]
			re, _ := regexp.Compile(";")
			split := re.Split(string(buf), -1)
			set := []string{}

			for i := range split {
				set = append(set, strings.Replace(split[i], "\n", "", -1))
			}

			address := set[0]
			var msg string

			if len(set) > 1 {
				msg = set[1]
			}

			switch {
			// SCAN request from java
			case strings.Contains(string(buf), "SCAN"):
				fmt.Println("Scanning...")
				// call scan function to search for nearby vehicles
				server.DiscoveredDevices = scan()
				for _, device := range server.DiscoveredDevices.Items() {
					// for each found device, send a tcp msg to java saying found
					conn.Write([]byte("SCAN;" + device.Address + ";" + device.ManufacturerData + ";" + device.LocalName + "\n"))

					fmt.Println("Found " + device.Address)
					time.Sleep(500 * time.Millisecond)
				}
				// Stops scanning on java side
				conn.Write([]byte("SCAN;COMPLETED\n"))
				fmt.Println("Scanning Completed.")

			// CONNECT request from java
			case strings.Contains(string(buf), "CONNECT"):
				// for each discovered device try to connect to the device

				bytes := []byte(set[1])
				var payload []byte
				for _, b := range bytes {
					if b != 0x00 {
						payload = append(payload, b)
					}
				}

				device, _ := server.DiscoveredDevices.Get(string(payload))

				connectedDevice, err := Adapter.Connect(device.Addresser, bluetooth.ConnectionParams{})
				if err != nil {
					log.Fatalln(err.Error())
				}

				server.ConnectedDevices.Set(device.Address, connectedDevice)
				fmt.Println("Connected to", device.Address)

				services, _ := connectedDevice.DiscoverServices([]bluetooth.UUID{ANKI_STR_SERVICE_UUID})
				if err != nil {
					fmt.Println("Failed to discover services")
					return
				}

				service := services[0]
				characteristics, _ := service.DiscoverCharacteristics([]bluetooth.UUID{ANKI_STR_CHR_READ_UUID, ANKI_STR_CHR_WRITE_UUID})
				server.DeviceCharacteristics.Set(device.Address, characteristics)

				readService := characteristics[1]

				// Each time the vehicle sends a msg through bluetooth, the event is triggered
				err = readService.EnableNotifications(func(value []byte) {
					encodedBytes := hex.EncodeToString(value)
					// Send the vehicle respond back to java
					conn.Write([]byte(device.Address + ";" + encodedBytes + "\n"))
					fmt.Println("RECEIVED: [" + device.Address + ";" + encodedBytes + "]")
				})
				if err != nil {
					return
				}
				// terminate connection request to java
				conn.Write([]byte("CONNECT;SUCCESS\n"))
				fmt.Println("CONNECT COMPLETED")

			//DISCONNECT request from java
			case strings.Contains(string(buf), "DISCONNECT"):
				// disconnect the vehicle with the address in the buffer
				connectedDevice, _ := server.ConnectedDevices.Get(address)
				connectedDevice.Disconnect()
				conn.Write([]byte("DISCONNECT;SUCCESS\n"))

			/* Any other request is assumed to be a command given to the car. Each byte in the buffer represents an action that is
			outlined in https://github.com/tenbergen/anki-drive-java/blob/master/Anki%20Drive%20Programming%20Guide.pdf
			*/
			default:
				if len(msg) != 6 {
				}
				if len(set) == 2 {
					// Get the writer characteristic
					characteristics, _ := server.DeviceCharacteristics.Get(address)

					writeService := characteristics[0]

					payload, _ := hex.DecodeString(msg)

					_, err := writeService.WriteWithoutResponse(payload)
					if err != nil {
						fmt.Println(err)
						return
					}

					fmt.Println("SENDING: [" + strings.Replace(string(buf), "\n", "", -1) + "]")
				}

			}
		}(buf)
	}
}

// function for scanning nearby vehicles returns a map of addresses to vehicles
func scan() cmap.ConcurrentMap[string, AnkiVehicle] {
	m := cmap.New[AnkiVehicle]()

	channel := make(chan string, 1)
	go func() {
		must("enable BLE stack", Adapter.Enable())

		err := Adapter.Scan(func(adapter *bluetooth.Adapter, device bluetooth.ScanResult) {
			if strings.Contains(device.LocalName(), "Drive") {
				if !m.Has(device.Address.String()) {
					var manufacturerData = ""
					for _, data := range device.ManufacturerData() {
						manufacturerData = "beef" + hex.EncodeToString(data)
					}
					var localname = ""
					if device.Address.String()[0:1] == "e" {
						localname = "10603001202020204472697665"
					} else {
						localname = "10603001202020204472697665"
					}
					m.Set(strings.Replace(device.Address.String(), "-", "", -1), AnkiVehicle{
						Address:          strings.Replace(device.Address.String(), "-", "", -1),
						ManufacturerData: manufacturerData,
						LocalName:        localname,
						Addresser:        device.Address,
					})
				}
			}
		})
		must("start scan", err)
		must("enable BLE stack", Adapter.StopScan())

		channel <- "finished scanning"
	}()

	select {
	case <-channel:
		break
	case <-time.After(5 * time.Second):
		break
	}

	return m
}

func must(action string, err error) {
	if err != nil {
		panic("failed to " + action + ": " + err.Error())
	}
}
