# Self-Hosted Map Tiles

This directory contains self-hosted map tiles for offline operation.

## Tile Structure

The tiles should be organized in the following structure:
```
/tiles/
├── {z}/
│   ├── {x}/
│   │   ├── {y}.png
│   │   └── ...
│   └── ...
└── ...
```

Where:
- `{z}` = zoom level (0-18)
- `{x}` = tile x coordinate
- `{y}` = tile y coordinate

## Tile Sources

You can generate tiles using tools like:

1. **TileMill** - Create custom map styles
2. **Mapnik** - Render tiles from OpenStreetMap data
3. **TileStache** - Serve tiles from various sources
4. **TileServer GL** - Modern tile server

## Quick Setup with TileServer GL

1. Install TileServer GL:
```bash
npm install -g tileserver-gl
```

2. Download OpenStreetMap data:
```bash
wget https://download.geofabrik.de/north-america/us/california-latest.osm.pbf
```

3. Generate tiles:
```bash
tileserver-gl --config config.json
```

## Configuration

The fallback map will look for tiles at:
- `/tiles/{z}/{x}/{y}.png` - Basic style
- `/tiles-dark/{z}/{x}/{y}.png` - Dark theme
- `/tiles-light/{z}/{x}/{y}.png` - Light theme
- `/tiles-satellite/{z}/{x}/{y}.png` - Satellite imagery

## Tile Generation Commands

### Using GDAL2Tiles
```bash
gdal2tiles.py -z 0-18 -w leaflet input.tif tiles/
```

### Using Mapnik
```bash
nik4.py --bbox -180,-85,180,85 --zoom 0-18 --format png --output tiles/{z}/{x}/{y}.png style.xml
```

## Storage Requirements

- Zoom levels 0-10: ~1GB
- Zoom levels 0-14: ~10GB
- Zoom levels 0-18: ~100GB+

For offline use, consider limiting to zoom levels 0-14 for reasonable storage requirements.

