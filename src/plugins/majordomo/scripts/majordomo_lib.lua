--[[
Copyright 2014, CZ.NIC z.s.p.o. (http://www.nic.cz/)

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
DB_PATH_DEFAULT="/tmp/majordomo_db/";

-- This names have to be synced with Majordomo plugin
KW_OTHER_PROTO = "both"
KW_OTHER_DSTIP = "all"
KW_OTHER_PORT = "all"


--[[
	Get configuration from corresponding UCI file
]]
function majordomo_get_configuration()
	local db_path;
	local make_lookup;
	local majordomocfg = uci.cursor();

	majordomocfg:foreach("majordomo", "db", function(s) if s[".type"] == "db" and s.path then db_path=s.path; return false; end return true; end);
	majordomocfg:foreach("majordomo", "statistics", function(s) if s[".type"] == "statistics" and s.make_lookup then make_lookup=s.make_lookup; return false; end return true; end);

	if not db_path then db_path = DB_PATH_DEFAULT; end
	if make_lookup == "1" then make_lookup = true; elseif make_lookup == "0" then make_lookup = false; else make_lookup = true; end

	return db_path, make_lookup;
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
				dbfile:write(key .. "=" .. value .. "\n");
			end
			dbfile:close();
		end
	end

	function result:deserialize()
		local dbfile = io.open(self.PATH .. "/" .. self.FILE_PREFIX .. self.name, "r");
		if dbfile then
			for line in dbfile:lines() do
				local key, value = line:match("(.*)=(.*)");
				if key and value then
					self.data[key] = value;
				end
			end
			dbfile:close();
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
function get_sorted_items(addr, items, by)
	-- Prepare array set to sorting
	sorted_array = {};
	for k, v in pairs(items) do
		table.insert(sorted_array, {key = k, value = v});
	end

	table.sort(sorted_array, function(x, y) return x.value[by] > y.value[by] end)

	return sorted_array;
end

function read_file(db, file)
	local f = io.open(file, "r");
	if not f then
		return false;
	end

	for line in f:lines() do
		--Use port as string... we need value "all"
		proto, src, dst, port, d_count, d_size, d_data_size, u_count, u_size, u_data_size = line:match("(%w+),([%w\.:]+),([%w\.:]+),(%w+),(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)");
		key = table.concat({ proto, src, dst, port }, ",");
		if (key ~= "") then
			if not db[src] then
				db[src] = { };
			end
			if not db[src][key] then
				db[src][key] = {
					d_count = tonumber(d_count), d_size = tonumber(d_size), d_data_size = tonumber(d_data_size),
					u_count = tonumber(u_count), u_size = tonumber(u_size), u_data_size = tonumber(u_data_size)
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

function split_key(key)
	return key:match("(%w+),([%w\.:]+),([%w\.:]+),(%w+)");
end

--[[
	Define DB for reverse domain lookup
]]
function get_inst_ptrdb()
	local db_path, _ = majordomo_get_configuration();
	local ptrdb = db("ptr", db_path);
	function ptrdb:lookup(key)
		-- Pick some "safe" string
		local empty_result = "none";
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

		local cached = self.data[key];
		if cached then
			if cached ~= empty_result then
				return cached;
			else
				return nil;
			end
		end

		local handle = io.popen("kdig -x " .. key);
		local ptr, nxdomain = parse(handle);

		local ret;
		if not ptr and nxdomain then
			self.data[key] = empty_result;
			ret = nil;
		elseif not ptr and not nxdomain then
			self.data[key] = empty_result;
			ret = nil;
		elseif ptr and not nxdomain then
			self.data[key] = ptr;
			ret = ptr;
		end
		handle:close();

		return ret;
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
		local empty_result = "none";

		local cached = self.data[key];
		if cached then
			if cached ~= empty_result then
				return cached;
			else
				return nil;
			end
		end

		local handle = io.popen("curl http://www.macvendorlookup.com/api/v2/" .. key .. "/pipe");
		local result = handle:read();
		handle:close();
		if not result then
			self.data[key] = empty_result;
			return nil;
		end
		local vendor = result:match("%w+|%w+|%w+|%w+|([%w%s]+).*");
		self.data[key]=vendor;
		return vendor;
	end

	return macdb
end

