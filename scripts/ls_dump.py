import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from idbutil import connect_ro
db = sys.argv[1]
# connect_ro, not a plain mode=ro open: on a WAL database that one creates -shm and -wal files
# beside the evidence (and it read nothing still in the log)
con = connect_ro(db)
KEYS = ["last-wid-md","WALid","WANoiseInfo","WANoiseInfoIv","WAWebEncKeySalt","WebEncKeySalt",
        "Session","CanonicalRegistrationTraceId","WACachedProfilePicEURL","WADailyStatsStartTime",
        "WALangPhonePref","banzai:last_storage_flush","calls_tab_last_seen","selected_audio_input_device",
        "WABotListLastRequestedTimestamp","UsernameState","abprops-refresh-id","RSTData",
        "wa_voip_fieldstats_handoff_dedup_v1","hour-24-from-phone","contact-sync-refresh-seconds",
        "WANewslettersWasBootstrapped","MutexBlockStrategy","AbpropsWebRefreshId"]
for k in KEYS:
    r = con.execute("SELECT compression_type,last_access_time,value FROM data WHERE key=?", (k,)).fetchone()
    if not r: continue
    comp, lat, val = r
    if comp != 0:
        print(f"[{k}] (compressed type={comp}, {len(val)}B) -- skipped"); continue
    try: s = val.decode('utf-8', 'replace')
    except Exception: s = repr(val)
    print(f"\n=== {k} ===")
    print(s[:900])
