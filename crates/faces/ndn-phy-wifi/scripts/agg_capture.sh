#!/usr/bin/env bash
# De-risk: can the MT7612U (mt76x2u) actually radiate AGGREGATED TX above the
# ~106 Mb/s single-MPDU ceiling? Bring it up as a VHT80 AP, connect the Realtek
# wlu1 as a STA (isolated in a netns so iperf traffic crosses the air, not
# loopback), and measure AP->STA downlink (wlan0 transmits). >106 Mb/s ⇒ the
# device aggregates ⇒ the userspace port to 200+ is worth doing.
set -u
SSID=ndnagg
HOSTAPD=$(nix build nixpkgs#hostapd --no-link --print-out-paths 2>/dev/null | grep -v -- '-man' | head -1)/bin/hostapd
log(){ echo "=== $* ==="; }

log "reset drivers"
sudo modprobe -r mt76x2u 2>/dev/null; sleep 1
sudo modprobe mt76x2u; sleep 4
AP=""; for n in /sys/class/net/wl*; do b=$(basename $n); d=$(basename $(readlink -f $n/device/driver) 2>/dev/null); [ "$d" = mt76x2u ] && AP=$b; done
[ -z "$AP" ] && { echo "NO mt76x2u iface"; sudo dmesg|grep -iE mt76|tail -4; exit 1; }
echo "AP iface=$AP (mt76, → netns ap)  STA iface=wlu1 (realtek, default ns)  hostapd=$HOSTAPD"
sudo nmcli device set $AP managed no 2>/dev/null
sudo nmcli device set wlu1 managed no 2>/dev/null
sudo rfkill unblock all 2>/dev/null

log "move the mt76 AP phy into netns ap (realtek phy can't move; mt76 can)"
sudo ip netns del ap 2>/dev/null
sudo ip netns add ap
APPHY=phy$(cat /sys/class/net/$AP/phy80211/index)
sudo iw phy $APPHY set netns name ap || { echo "mt76 netns move FAILED"; exit 1; }
sleep 1
NS="sudo ip netns exec ap"
# phy resets to world regdom on netns move → 5GHz NO-IR; restore US and CONFIRM it
# applied before hostapd (a reg race shows up as COUNTRY_UPDATE->DISABLED).
for i in $(seq 1 8); do $NS iw reg set US 2>/dev/null; sleep 1; $NS iw reg get 2>/dev/null | grep -q "country US" && break; done
echo "netns reg: $($NS iw reg get 2>/dev/null | grep -m1 country)"

log "start hostapd VHT80 ch36 on $AP (in ap netns)"
cat >/tmp/hostapd.conf <<EOF
interface=$AP
driver=nl80211
ssid=$SSID
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ac=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]
vht_capab=[SHORT-GI-80][MAX-A-MPDU-LEN-EXP7]
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
wmm_enabled=1
EOF
# Do NOT pre-up the iface — hostapd manages interface state itself. Background via
# the shell (not -B) so the log is captured even if init fails early. Try VHT80;
# on COUNTRY_UPDATE->DISABLED (reg race / 80MHz unavailable) fall back to HT40.
start_ap(){
  sudo pkill hostapd 2>/dev/null; sleep 1
  $NS $HOSTAPD "$1" >/tmp/hostapd.log 2>&1 &
  for i in $(seq 1 10); do grep -q "AP-ENABLED" /tmp/hostapd.log && return 0; grep -q "DISABLED->DISABLED\|wasn.t started\|Failed to" /tmp/hostapd.log && return 1; sleep 1; done
  return 1
}
if start_ap /tmp/hostapd.conf; then echo "AP up: VHT80"; else
  echo "VHT80 failed:"; grep -iE "DISABLED|NO_IR|Could not|Failed|not allowed" /tmp/hostapd.log | tail -4
  # HT40 fallback
  sed -i 's/^ieee80211ac=1/ieee80211ac=0/; /^vht_/d' /tmp/hostapd.conf
  if start_ap /tmp/hostapd.conf; then echo "AP up: HT40 (VHT80 unavailable)"; else echo "!! AP NOT ENABLED (HT40 too)"; grep -iE "DISABLED|Failed" /tmp/hostapd.log|tail -3; fi
fi

log "connect wlu1 (default ns) via wpa_supplicant (assoc BEFORE capture)"
sudo ip link set wlu1 down 2>/dev/null; sudo iw dev wlu1 set type managed 2>/dev/null; sudo ip link set wlu1 up
cat >/tmp/wpa.conf <<EOF
network={ ssid="$SSID"
    key_mgmt=NONE
    scan_ssid=1 }
EOF
sudo pkill wpa_supplicant 2>/dev/null; sleep 1
sudo wpa_supplicant -B -i wlu1 -c /tmp/wpa.conf -D nl80211 2>&1 | tail -1
for i in $(seq 1 25); do st=$(sudo iw dev wlu1 link 2>/dev/null|grep -i "Connected to"); [ -n "$st" ] && break; sleep 1; done
echo "STA: ${st:-NOT CONNECTED}"
[ -z "$st" ] && { echo "ABORT: no assoc"; sudo pkill hostapd wpa_supplicant 2>/dev/null; sudo ip netns del ap 2>/dev/null; echo DONE; exit 0; }
sudo ip addr add 192.168.99.1/24 dev $AP 2>/dev/null
sudo ip addr add 192.168.99.2/24 dev wlu1 2>/dev/null

log "START usbmon6 capture (BA setup + aggregated TX), snaplen 320"
sudo rm -f /tmp/agg_full.pcap
sudo timeout 6 tcpdump -i usbmon6 -s 320 -w /tmp/agg_full.pcap 2>/dev/null &
TPID=$!
sleep 1
iperf3 -s -D -1 2>/dev/null; sleep 1
timeout 8 bash -c "$NS iperf3 -c 192.168.99.2 -t 3 2>&1" | tail -6
wait $TPID 2>/dev/null
echo "pcap: $(ls -l /tmp/agg_full.pcap 2>/dev/null | awk '{print $5}') bytes"
log "AP station dump"
$NS iw dev $AP station dump 2>/dev/null | grep -iE "tx bitrate|tx packets"
sudo pkill hostapd wpa_supplicant 2>/dev/null
sudo ip netns del ap 2>/dev/null
echo DONE
