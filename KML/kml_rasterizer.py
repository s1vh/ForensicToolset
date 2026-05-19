python3 - <<'PY'
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

tree = ET.parse("S3cr3t.kml")
root = tree.getroot()

ns = {"k": "http://www.opengis.net/kml/2.2"}
coords_text = root.find(".//k:coordinates", ns).text

lats = []
lons = []

for item in coords_text.split():
    lon, lat, *_ = item.split(",")
    lons.append(float(lon))
    lats.append(float(lat))

plt.figure(figsize=(12, 5))
plt.plot(lats, lons, linewidth=4)
plt.gca().set_aspect("equal", adjustable="box")
plt.axis("off")
plt.savefig("S3cr3t_password.png", dpi=200, bbox_inches="tight")

print("[+] Imagen generada: S3cr3t_password.png")
PY
