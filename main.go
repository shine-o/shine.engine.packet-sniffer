package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
)

var iface string
var snaplen int
var filter string
var knownServices = make(map[int]*service) // port => serviceName

func init() {
	viperConfig()

	// remove output folder if exists, create it again
	dir, err := filepath.Abs("output/")
	fmt.Println(dir)
	if _, err := os.Stat(dir); os.IsNotExist(err) {

	} else {
		err = os.RemoveAll(dir)
		logError(err)
	}

	err = os.Mkdir(dir, 0700)
	logError(err)

	iface = viper.GetString("network.interface")
	snaplen = viper.GetInt("network.snaplen")

	serverIp := viper.GetString("network.serverIp")
	startPort := viper.GetString("network.portRange.start")
	endPort := viper.GetString("network.portRange.end")
	portRange := fmt.Sprintf("%v-%v", startPort, endPort)

	filter = fmt.Sprintf("(dst net %v or src net %v) and (dst portrange %v or src portrange %v)", serverIp, serverIp, portRange, portRange)

	xorKey, err = hex.DecodeString(viper.GetString("protocol.xorTableHexString"))

	if viper.IsSet("protocol.services") {
		// snippet for loading yaml array
		services := make([]map[string]string, 0)
		var m map[string]string
		servicesI := viper.Get("protocol.services")
		servicesS := servicesI.([]interface{})
		for _, s := range servicesS {
			serviceMap := s.(map[interface{}]interface{})
			m = make(map[string]string)
			for k, v := range serviceMap {
				m[k.(string)] = v.(string)
			}
			services = append(services, m)
		}
		for _, v := range services {
			port, err := strconv.Atoi(v["port"])
			logError(err)
			knownServices[port] = &service{name: v["name"]}
		}
	} else {
		knownServices[9000] = &service{name: "Account"}
		knownServices[9311] = &service{name: "AccountLog"}
		knownServices[9411] = &service{name: "Character"}
		knownServices[9511] = &service{name: "GameLog"}
		knownServices[9010] = &service{name: "Login"}
		knownServices[9110] = &service{name: "WorldManager"}
		knownServices[9210] = &service{name: "Zone00"}
		knownServices[9212] = &service{name: "Zone01"}
		knownServices[9214] = &service{name: "Zone02"}
		knownServices[9216] = &service{name: "Zone03"}
		knownServices[9218] = &service{name: "Zone04"}
	}
}

func viperConfig() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory

	err := viper.ReadInConfig() // Find and read the config file
	panicError(err)

	required := []string{
		"network.interface",
		"network.serverIp",
	}

	for _, v := range required {
		if !viper.IsSet(v) {
			panic(fmt.Sprintf("required config parameter is missing: %v", v))
		}
	}

	//if !viper.IsSet("network.portRange.start") {
	//}
	//
	//if !viper.IsSet("network.portRange.end") {
	//}

	viper.SetDefault("network.portRange.start", 9000)

	viper.SetDefault("network.portRange.end", 9600)

	viper.SetDefault("network.interface", 65536)

	viper.SetDefault("protocol.xorTableHexString", "0759694a941194858c8805cba09ecd583a365b1a6a16febddf9402f82196c8e99ef7bfbdcfcdb27a009f4022fc11f90c2e12fba7740a7d78401e2ca02d06cba8b97eefde49ea4e13161680f43dc29ad486d7942417f4d665bd3fdbe4e10f50f6ec7a9a0c273d2466d322689c9a520be0f9a50b25da80490dfd3e77d156a8b7f40f9be80f5247f56f832022db0f0bb14385c1cba40b0219dff08becdb6c6d66ad45be89147e2f8910b89360d860def6fe6e9bca06c1759533cfc0b2e0cca5ce12f6e5b5b426c5b2184f2a5d261b654df545c98414dc7c124b189cc724e73c64ffd63a2cee8c8149396cb7dcbd94e232f7dd0afc020164ec4c940ab156f5c9a934de0f3827bc81300f7b3825fee83e29ba5543bf6b9f1f8a4952187f8af888245c4fe1a830878e501f2fd10cb4fd0abcdc1285e252ee4a5838abffc63db960640ab450d54089179ad585cfec0d7e817fe3c3040122ec27ccfa3e21a654c8de00b6df279ff625340785bfa7a5a5e0830c3d5d2040af60a36456f305c41c7d3798c3e85a6e5885a49a6b6af4a37b619b09401e604b32d951a4fef95d4e4afb4ad47c330233d59dce5baa5a7cd8f805fa1f2b8c725750ae6c1989ca01fcfc299b61126863654626c45b50aa2bbeef9a790223752c2013fdd95a7623f10bb5b859f99f7ae606e9a53ab450bf165898b39a6e36ee8deb")

	viper.SetDefault("protocol.xorLimit", 350)

	viper.SetDefault("protocol.log.client", true)

	viper.SetDefault("protocol.log.server", true)
}

func logError(e error) {
	if e != nil {
		log.Println(e)
	}
}

func panicError(e error) {

}

// for each service, start a goroutine with listener
func main() {
	pf := &Flows{
		pfm: make(map[string][]gopacket.Packet),
	}

	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer func() {
		signal.Stop(c)
		cancel()
	}()

	go listen(ctx, pf)

	select {
	case <-c:
		pf.persist()
		persistXorKeys()
		cancel()
	case <-ctx.Done():
		pf.persist()
	}

}

func listen(ctx context.Context, pf *Flows) {

	sf := &fiestaStreamFactory{}

	sp := tcpassembly.NewStreamPool(sf)
	a := tcpassembly.NewAssembler(sp)

	if handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil { //
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go pf.add(packet)
			tcp := packet.TransportLayer().(*layers.TCP)
			a.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
}
