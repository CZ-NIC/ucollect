--[[
Copyright 2014, 2015 CZ.NIC z.s.p.o. (http://www.nic.cz/)

This script is part of majordomo plugin for ucollect

NUCI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NUCI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NUCI.  If not, see <http://www.gnu.org/licenses/>.
]]

require("uci");

-- Definition of important constants
DAILY_PREFIX="majordomo_daily_";
HOURLY_PREFIX="majordomo_hourly_";
MONTHLY_PREFIX="majordomo_monthly_";
MONTHLY_ORIGIN_PREFIX="majordomo_origin_monthly_";
DB_PATH_DEFAULT="/tmp/majordomo_db/";
USE_DNS_LOOKUP_BACKEND = "nslookup_openwrt"
MAX_ITEMS_PER_CLIENT_DEFAULT = 6000
CACHE_RECORD_VALIDITY = 60 * 60 * 24 * 7; -- 7 days
CACHE_EMPTY_NAME = "none"

-- This names have to be synced with Majordomo plugin
KW_OTHER_PROTO = "both"
KW_OTHER_DSTIP = "other"
KW_OTHER_PORT = "all"


--[[
	Get configuration from corresponding UCI file
]]
function majordomo_get_configuration()
	local db_path;
	local make_lookup_dns;
	local max_items_per_client;
	local majordomocfg = uci.cursor();

	-- Find in config
	majordomocfg:foreach("majordomo", "db", function(s) if s[".type"] == "db" and s.path then db_path=s.path; return false; end return true; end);
	majordomocfg:foreach("majordomo", "db", function(s) if s[".type"] == "db" and s.max_items_per_client then max_items_per_client=tonumber(s.max_items_per_client); return false; end return true; end);
	majordomocfg:foreach("majordomo", "lookup", function(s) if s[".type"] == "lookup" and s.make_lookup_dns then make_lookup_dns=s.make_lookup_dns; return false; end return true; end);

	return db_path, true, make_lookup_dns, max_items_per_client;
end

--[[
	Virtual class for generic cache

	Is necessary to define lookup method
]]
function db(name, storage)
	local result = { };
	-- Constants
	result.FILE_PREFIX = "majordomo_serialized_";
	-- Properties
	result.PATH = storage;
	result.name = name;
	result.data = {};

	function result:serialize()
		local dbfile = io.open(self.PATH .. "/" .. self.FILE_PREFIX .. self.name, "w");
		if dbfile then
			for key, value in pairs(self.data) do
				dbfile:write(key .. "," .. value.ts .. "," .. value.payload .. "\n");
			end
			dbfile:close();
		end
	end

	function result:deserialize()
		local dbfile = io.open(self.PATH .. "/" .. self.FILE_PREFIX .. self.name, "r");
		if dbfile then
			for line in dbfile:lines() do
				local key, ts, payload = line:match("^([^,]*),([^,]*),(.*)$");
				if key and payload and ts then
					self.data[key] = { payload = payload, ts = tonumber(ts) };
				end
			end
			dbfile:close();
		end
	end

	function result:check(key)
		local value = self.data[key];
		if value then
			if value.ts < os.time() - CACHE_RECORD_VALIDITY then
				self.data[key] = nil;
			end
		end
	end

	function result:lookup(key)
		return nil;
	end

	return result;
end

--[[
	This function is capable to sort any key - value structure

	Function expects composite value part
]]
function get_sorted_items(items, by)
	-- Prepare array set to sorting
	sorted_array = {};
	for k, v in pairs(items) do
		table.insert(sorted_array, {key = k, value = v});
	end

	table.sort(sorted_array, function(x, y) return x.value[by] > y.value[by] end)

	return sorted_array;
end

DD_PROTO = 1;
DD_SRC = 2;
DD_DST = 3;
DD_PORT = 4;
DD_D_CNT = 5;
DD_D_SIZE = 6;
DD_D_DSIZE = 7;
DD_U_CNT = 8;
DD_U_SIZE = 9;
DD_U_DSIZE = 10;
DD_RESOLVED = 11;

DD = {
--	Match expr, default value, print format
	{"(%w+)", nil, "%s"},
	{"([%w\.:]+)", nil, "%s"},
	{"([%w\.:]+)", nil, "%s"},
	{"(%w+)", nil, "%s"},
	{"([%d.]+)", nil, "%f"},
	{"([%d.]+)", nil, "%f"},
	{"([%d.]+)", nil, "%f"},
	{"([%d.]+)", nil, "%f"},
	{"([%d.]+)", nil, "%f"},
	{"([%d.]+)", nil, "%f"},
	{"([%w_.-]+)", CACHE_EMPTY_NAME, "%s"},
}

function restore_line(data)
	local res = "";
	for i, record in ipairs(DD) do
		local fmt = record[3];

		if res == "" then
			res = string.format(fmt, data[i]);
		else
			res = string.format("%s,"..fmt, res, data[i]);
		end
	end

	return res;
end

function parse_line(line)
	local values = {}
	local rest = line;
	for _, record in ipairs(DD) do
		local match = record[1];
		local default = record[2];

		if rest and rest ~= "" then
			val, rest = rest:match("^"..match..",*(.*)$");
			table.insert(values, val);
		else
			table.insert(values, default);
		end
	end

	return values;
end

function read_file(db, file)
	local f = io.open(file, "r");
	if not f then
		return false;
	end

	for line in f:lines() do
		local col = parse_line(line);
		local proto = col[DD_PROTO];
		local src = col[DD_SRC];
		local dst = col[DD_DST];
		--Use port as string... we need value "all"
		local port = col[DD_PORT];
		local d_count = col[DD_D_CNT];
		local d_size = col[DD_D_SIZE];
		local d_data_size = col[DD_D_DSIZE];
		local u_count = col[DD_U_CNT];
		local u_size = col[DD_U_SIZE];
		local u_data_size = col[DD_U_DSIZE];
		local resolved_name = col[DD_RESOLVED];
		local key = table.concat({ proto, src, dst, port }, ",");
		if (key ~= "") then
			if not db[src] then
				db[src] = { };
			end
			if not db[src][key] then
				db[src][key] = {
					d_count = tonumber(d_count), d_size = tonumber(d_size), d_data_size = tonumber(d_data_size),
					u_count = tonumber(u_count), u_size = tonumber(u_size), u_data_size = tonumber(u_data_size),
					resolved_name = resolved_name
				}
			else
				db[src][key].d_count = db[src][key].d_count + tonumber(d_count);
				db[src][key].d_size = db[src][key].d_size + tonumber(d_size);
				db[src][key].d_data_size = db[src][key].d_data_size + tonumber(d_data_size);
				db[src][key].u_count = db[src][key].u_count + tonumber(u_count);
				db[src][key].u_size = db[src][key].u_size + tonumber(u_size);
				db[src][key].u_data_size = db[src][key].u_data_size + tonumber(u_data_size);
			end
		end
	end

	f:close();

	return true;
end

--[[
	Split "serialized" key

	Returns proto, src, dst, port
]]
function split_key(key)
	return key:match("(%w+),([%w\.:]+),([%w\.:]+),(%w+)");
end

local DNS_LOOKUP_BACKENDS = {
	["kdig"] = function(addr)
		-- Unfortunately, lua don't have break
		local parse = function(handle)
			for line in handle:lines() do
				if string.find(line, "NXDOMAIN") then
					return nil, true;
				end

				local rev = line:match("[%.%w]+%s+%d+%s+IN%s+PTR%s+([%.%-%_%w]+).*");
				if rev then
					return rev, nil;
				end
			end
			return nil, nil;
		end

		local handle = io.popen("kdig -x " .. addr);
		local ptr, nxdomain = parse(handle);
		handle:close();

		return ptr, nxdomain;
	end
	,
	["nslookup_openwrt"] = function(addr)
		local parse = function(handle, addr)
			for line in handle:lines() do
				if string.find(line, "Name or service not known") then
					return nil, true;
				end

				if string.find(line, addr) then
					local rev = line:match("Address%s+%d+:%s+[%w%.%:]+%s+([%.%-%_%w]+).*");
					if rev then
						return rev, nil;
					end
				end
			end
			return nil, nil;
		end

		local handle = io.popen("busybox nslookup " .. addr);
		local ptr, nxdomain = parse(handle, addr);
		handle:close();

		return ptr, nxdomain;
	end
	};


--[[
	Define DB for reverse domain lookup
]]
function get_inst_ptrdb()
	local db_path, _ = majordomo_get_configuration();
	local ptrdb = db("ptr", db_path);
	function ptrdb:lookup(key)
		-- Pick some "safe" string
		local empty_result = CACHE_EMPTY_NAME;
		local resolve = DNS_LOOKUP_BACKENDS[USE_DNS_LOOKUP_BACKEND];

		local cached = self.data[key];
		if cached then
			if cached.payload ~= empty_result then
				return cached.payload;
			else
				return nil;
			end
		end

		local ptr, nxdomain = resolve(key);
		if not ptr and nxdomain then
			self.data[key] = { payload = empty_result, ts = os.time() };
			return nil;
		elseif not ptr and not nxdomain then
			self.data[key] = { payload = empty_result, ts = os.time() };
			return nil;
		elseif ptr and not nxdomain then
			self.data[key] = { payload = ptr, ts = os.time() };
			return ptr;
		end
	end

	return ptrdb
end

--[[
	Define DB for MAC address vendor lookup
]]
function get_inst_macdb()
	local db_path, _ = majordomo_get_configuration();
	-- Define DB for MAC address vendor lookup
	local macdb = db("mac_vendor", db_path);
	function macdb:lookup(key)
		-- Pick some "safe" string
		local empty_result = CACHE_EMPTY_NAME;

		local cached = self.data[key];
		if cached then
			if cached.payload ~= empty_result then
				return cached.payload;
			else
				return nil;
			end
		end

		local handle = io.popen("ouidb " .. key);
		local result = handle:read();
		handle:close();

		local vendor = result and result:match("^(.*)$");

		if not vendor then
			self.data[key] = { payload = empty_result, ts = os.time() };
			return nil;
		end
		self.data[key] = { payload = vendor, ts = os.time() };
		return vendor;
	end

	return macdb
end

--[[
	Iterate over static_name options and return list of defined names
]]
function get_static_names_list()
	local cur = uci.cursor();
	local list = {};

	cur:foreach("majordomo", "static_name", function(i) if i.mac then list[i.mac] = i.name; end; end);

	return list;
end
