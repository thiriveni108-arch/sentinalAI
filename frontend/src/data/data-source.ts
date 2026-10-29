import "server-only";
import { fixtureDataSource } from "@/data/fixture-data-source";
import { HttpDataSource } from "@/data/http-data-source";
import type { SentinelDataSource } from "@/data/sentinel-data-source";

let selected: SentinelDataSource | undefined;

export function getSentinelDataSource(): SentinelDataSource {
  if (selected) return selected;
  selected = process.env.SENTINEL_DATA_SOURCE?.toLowerCase() === "http"
    ? new HttpDataSource(
        (process.env.SENTINEL_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, ""),
        process.env.SENTINEL_API_KEY,
      )
    : fixtureDataSource;
  return selected;
}
