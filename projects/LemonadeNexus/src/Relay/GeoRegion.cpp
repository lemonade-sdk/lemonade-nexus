#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <algorithm>
#include <cmath>
#include <limits>

namespace nexus::relay {

// ---------------------------------------------------------------------------
// Region database: US states + international regions
// Centroids are approximate geographic centers (latitude, longitude).
// ---------------------------------------------------------------------------

static const std::vector<RegionInfo> kRegions = {
    // --- US States ---
    {"us-al", "Alabama",              {32.806671, -86.791130}},
    {"us-ak", "Alaska",               {61.370716, -152.404419}},
    {"us-az", "Arizona",              {33.729759, -111.431221}},
    {"us-ar", "Arkansas",             {34.969704, -92.373123}},
    {"us-ca", "California",           {36.116203, -119.681564}},
    {"us-co", "Colorado",             {39.059811, -105.311104}},
    {"us-ct", "Connecticut",          {41.597782, -72.755371}},
    {"us-de", "Delaware",             {39.318523, -75.507141}},
    {"us-fl", "Florida",              {27.766279, -81.686783}},
    {"us-ga", "Georgia",              {33.040619, -83.643074}},
    {"us-hi", "Hawaii",               {21.094318, -157.498337}},
    {"us-id", "Idaho",                {44.240459, -114.478828}},
    {"us-il", "Illinois",             {40.349457, -88.986137}},
    {"us-in", "Indiana",              {39.849426, -86.258278}},
    {"us-ia", "Iowa",                 {42.011539, -93.210526}},
    {"us-ks", "Kansas",               {38.526600, -96.726486}},
    {"us-ky", "Kentucky",             {37.668140, -84.670067}},
    {"us-la", "Louisiana",            {31.169546, -91.867805}},
    {"us-me", "Maine",                {44.693947, -69.381927}},
    {"us-md", "Maryland",             {39.063946, -76.802101}},
    {"us-ma", "Massachusetts",        {42.230171, -71.530106}},
    {"us-mi", "Michigan",             {43.326618, -84.536095}},
    {"us-mn", "Minnesota",            {45.694454, -93.900192}},
    {"us-ms", "Mississippi",          {32.741646, -89.678696}},
    {"us-mo", "Missouri",             {38.456085, -92.288368}},
    {"us-mt", "Montana",              {46.921925, -110.454353}},
    {"us-ne", "Nebraska",             {41.125370, -98.268082}},
    {"us-nv", "Nevada",               {38.313515, -117.055374}},
    {"us-nh", "New Hampshire",        {43.452492, -71.563896}},
    {"us-nj", "New Jersey",           {40.298904, -74.521011}},
    {"us-nm", "New Mexico",           {34.840515, -106.248482}},
    {"us-ny", "New York",             {42.165726, -74.948051}},
    {"us-nc", "North Carolina",       {35.630066, -79.806419}},
    {"us-nd", "North Dakota",         {47.528912, -99.784012}},
    {"us-oh", "Ohio",                 {40.388783, -82.764915}},
    {"us-ok", "Oklahoma",             {35.565342, -96.928917}},
    {"us-or", "Oregon",               {44.572021, -122.070938}},
    {"us-pa", "Pennsylvania",         {40.590752, -77.209755}},
    {"us-ri", "Rhode Island",         {41.680893, -71.511780}},
    {"us-sc", "South Carolina",       {33.856892, -80.945007}},
    {"us-sd", "South Dakota",         {44.299782, -99.438828}},
    {"us-tn", "Tennessee",            {35.747845, -86.692345}},
    {"us-tx", "Texas",                {31.054487, -97.563461}},
    {"us-ut", "Utah",                 {40.150032, -111.862434}},
    {"us-vt", "Vermont",              {44.045876, -72.710686}},
    {"us-va", "Virginia",             {37.769337, -78.169968}},
    {"us-wa", "Washington",           {47.400902, -121.490494}},
    {"us-wv", "West Virginia",        {38.491226, -80.954453}},
    {"us-wi", "Wisconsin",            {44.268543, -89.616508}},
    {"us-wy", "Wyoming",              {42.755966, -107.302490}},
    {"us-dc", "District of Columbia", {38.897438, -77.026817}},

    // --- Canada ---
    {"ca-on", "Ontario",              {51.253775, -85.323214}},
    {"ca-qc", "Quebec",               {52.939916, -73.549136}},
    {"ca-bc", "British Columbia",     {53.726669, -127.647621}},
    {"ca-ab", "Alberta",              {53.933271, -116.576503}},

    // --- Europe ---
    {"eu-gb", "United Kingdom",       {55.378051, -3.435973}},
    {"eu-de", "Germany",              {51.165691, 10.451526}},
    {"eu-fr", "France",               {46.227638, 2.213749}},
    {"eu-nl", "Netherlands",          {52.132633, 5.291266}},
    {"eu-se", "Sweden",               {60.128161, 18.643501}},
    {"eu-fi", "Finland",              {61.924110, 25.748151}},
    {"eu-no", "Norway",               {60.472024, 8.468946}},
    {"eu-ie", "Ireland",              {53.142367, -7.692054}},
    {"eu-es", "Spain",                {40.463667, -3.749220}},
    {"eu-it", "Italy",                {41.871940, 12.567380}},
    {"eu-pl", "Poland",               {51.919438, 19.145136}},
    {"eu-ch", "Switzerland",          {46.818188, 8.227512}},
    {"eu-at", "Austria",              {47.516231, 14.550072}},
    {"eu-pt", "Portugal",             {39.399872, -8.224454}},
    {"eu-be", "Belgium",              {50.503887, 4.469936}},
    {"eu-dk", "Denmark",              {56.263920, 9.501785}},
    {"eu-cz", "Czech Republic",       {49.817492, 15.472962}},
    {"eu-ro", "Romania",              {45.943161, 24.966760}},

    // --- Asia Pacific ---
    {"ap-jp", "Japan",                {36.204824, 138.252924}},
    {"ap-kr", "South Korea",          {35.907757, 127.766922}},
    {"ap-sg", "Singapore",            {1.352083, 103.819836}},
    {"ap-au", "Australia",            {-25.274398, 133.775136}},
    {"ap-nz", "New Zealand",          {-40.900557, 174.885971}},
    {"ap-in", "India",                {20.593684, 78.962880}},
    {"ap-hk", "Hong Kong",            {22.396428, 114.109497}},
    {"ap-tw", "Taiwan",               {23.697810, 120.960515}},
    {"ap-id", "Indonesia",            {-0.789275, 113.921327}},
    {"ap-th", "Thailand",             {15.870032, 100.992541}},
    {"ap-ph", "Philippines",          {12.879721, 121.774017}},
    {"ap-vn", "Vietnam",              {14.058324, 108.277199}},

    // --- Middle East ---
    {"me-ae", "UAE",                  {23.424076, 53.847818}},
    {"me-il", "Israel",               {31.046051, 34.851612}},
    {"me-sa", "Saudi Arabia",         {23.885942, 45.079162}},

    // --- South America ---
    {"sa-br", "Brazil",               {-14.235004, -51.925280}},
    {"sa-ar", "Argentina",            {-38.416097, -63.616672}},
    {"sa-cl", "Chile",                {-35.675147, -71.542969}},
    {"sa-co", "Colombia",             {4.570868, -74.297333}},

    // --- Africa ---
    {"af-za", "South Africa",         {-30.559482, 22.937506}},
    {"af-ng", "Nigeria",              {9.081999, 8.675277}},
    {"af-ke", "Kenya",                {-0.023559, 37.906193}},
    {"af-eg", "Egypt",                {26.820553, 30.802498}},
};

// ---------------------------------------------------------------------------
// Haversine formula
// ---------------------------------------------------------------------------

double GeoRegion::deg_to_rad(double deg) {
    return deg * (M_PI / 180.0);
}

double GeoRegion::haversine_km(const GeoCoord& a, const GeoCoord& b) {
    double lat1 = deg_to_rad(a.latitude);
    double lat2 = deg_to_rad(b.latitude);
    double dlat = deg_to_rad(b.latitude - a.latitude);
    double dlon = deg_to_rad(b.longitude - a.longitude);

    double h = std::sin(dlat / 2.0) * std::sin(dlat / 2.0) +
               std::cos(lat1) * std::cos(lat2) *
               std::sin(dlon / 2.0) * std::sin(dlon / 2.0);

    double c = 2.0 * std::atan2(std::sqrt(h), std::sqrt(1.0 - h));
    return kEarthRadiusKm * c;
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

const std::vector<RegionInfo>& GeoRegion::all_regions() {
    return kRegions;
}

bool GeoRegion::is_valid_region(std::string_view code) {
    return lookup(code).has_value();
}

std::optional<RegionInfo> GeoRegion::lookup(std::string_view code) {
    // Lowercase comparison
    std::string lower(code);
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return std::tolower(c); });

    for (const auto& r : kRegions) {
        if (r.code == lower) return r;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Distance
// ---------------------------------------------------------------------------

std::optional<double> GeoRegion::distance_between_regions(
    std::string_view region_a, std::string_view region_b) {
    auto a = lookup(region_a);
    auto b = lookup(region_b);
    if (!a || !b) return std::nullopt;
    return haversine_km(a->centroid, b->centroid);
}

// ---------------------------------------------------------------------------
// Closest region
// ---------------------------------------------------------------------------

std::optional<RegionInfo> GeoRegion::find_closest_region(const GeoCoord& coord) {
    if (kRegions.empty()) return std::nullopt;

    const RegionInfo* best = nullptr;
    double best_dist = std::numeric_limits<double>::max();

    for (const auto& r : kRegions) {
        double d = haversine_km(coord, r.centroid);
        if (d < best_dist) {
            best_dist = d;
            best = &r;
        }
    }

    return best ? std::optional<RegionInfo>(*best) : std::nullopt;
}

std::optional<RegionInfo> GeoRegion::find_closest_region(std::string_view region_code) {
    auto origin = lookup(region_code);
    if (!origin) return std::nullopt;

    const RegionInfo* best = nullptr;
    double best_dist = std::numeric_limits<double>::max();

    for (const auto& r : kRegions) {
        if (r.code == origin->code) continue; // Skip self
        double d = haversine_km(origin->centroid, r.centroid);
        if (d < best_dist) {
            best_dist = d;
            best = &r;
        }
    }

    return best ? std::optional<RegionInfo>(*best) : std::nullopt;
}

// ---------------------------------------------------------------------------
// Sort by distance
// ---------------------------------------------------------------------------

std::vector<std::string> GeoRegion::sort_by_distance(
    std::string_view from_region,
    const std::vector<std::string>& candidates) {

    auto origin = lookup(from_region);
    if (!origin) return candidates; // Can't sort without a valid origin

    struct Candidate {
        std::string code;
        double      distance;
    };

    std::vector<Candidate> sorted;
    std::vector<std::string> unknown;

    for (const auto& c : candidates) {
        auto info = lookup(c);
        if (info) {
            sorted.push_back({c, haversine_km(origin->centroid, info->centroid)});
        } else {
            unknown.push_back(c);
        }
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const Candidate& a, const Candidate& b) {
                  return a.distance < b.distance;
              });

    std::vector<std::string> result;
    result.reserve(candidates.size());
    for (auto& s : sorted) result.push_back(std::move(s.code));
    for (auto& u : unknown) result.push_back(std::move(u));
    return result;
}

} // namespace nexus::relay
