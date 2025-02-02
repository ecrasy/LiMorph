#pragma once

#include "Utils/Offsets.h"
#include "Memory/Memory.h"
#include "Thread/MainThread.h"
#include "Lexer/Lexer.h"
#include "Utils/WoWUtils.h"
#include "Utils/VMTHook.h"
#include "Player.h"

//12E0
namespace LiMorph {

// { "maxWoWAddress", "48 8B 05 ? ? ? 01 48 85 D2 74 09 48 85 C0 0F 85 ? 00 00 00", SignatureType::NORMAL, 0x3, 0x0 },
class Morpher
{
public:
	Morpher() {}
	~Morpher() {}
	void startMorpher();

	inline void setBaseAddress(uintptr_t base_address) {
		m_base_address = base_address;
	}

	inline uintptr_t getBaseAddress() {
		return m_base_address;
	}

	inline VMTHook* getVMTHook() {
		return m_hook;
	}

private:
	// printing in wow
	void SendWoWMessage(const std::string& message, const std::string& color);
	void SendWoWMessage(uintptr_t lua_state, const std::string& message, const std::string& color);
	void reportParseError(const std::string& message);

	// load lua code into c++
	static const char* getMountEventLuaCode();
	static const char* getParseChatLuaCode();
	static const char* getClickMorphingCode();
	static const char* getClickMountMorphingCode();

	// lua callbacks (for LUA API)
	static int chatCallback(uintptr_t lua_state);
	static int initLM(uintptr_t lua_state);
	static int customMessage(uintptr_t lua_state);
	static int mountCallback(uintptr_t lua_state);
	static int morphItemCallback(uintptr_t lua_state);
	static int morphEnchantCallback(uintptr_t lua_state);
	static int morphMountCallback(uintptr_t lua_state);

	// main thread callbacks
	static void initializeMorpherCallback();
	static void hookingCallback();
	static void registerFunctions();
	static void registerLuaEvents();
	static void zoningCallback();

	// methods called by main thread callbacks
	void zoning();
	void initializeMorpher();
	void hookFunctions();

	// CGUnit_C__UpdateDisplayInfo callback
	static void __fastcall updateDisplayInfoHook(uintptr_t unit);

	void updateDisplayInfoCustom(uintptr_t unit);

	// update model
	void updateModel();
	void forceUpdateModel();

	// get pointer to player unit
	uintptr_t getPlayerPtr();
	int getTargetMorphID();

	// morphing (some of which are caleld by the LUA callbacks above)
	void morphShapeshift(ShapeshiftForm form_id, int morph_id);
	void smartMorphShapeshift(bool set_original=true);
	void morphRace(int race_id);
	void morphGender(int gender_id);
	void updateGender(int gender_id);
	void morphItem(int item, int item_id, int item_version);
	void morphEnchant(int item, int enchant_id);
	void morphMount();
	void morphMountByID(int mount_id);
	void morphTitle(int title_id);

	// chat parsing
	void parseChat(uintptr_t lua_state);
	void parseMorph();
	void parseRace();
	void parseGender();
	void parseItem();
	void parseEnchant();
	void parseMount();
	void parseTitle();
	void parseShapeshift();
	void parseCommands();
	void parseMorphNPC();
	void parseNPCID();
	void parseCustomizations();
	void parseCustomizationOption(const std::string& str);
	void parseScale();
	void resetMorpher();
	static DWORD WINAPI testTest(LPVOID lpParam);
	uintptr_t iterateObjMgr();

	int m_func;

	uintptr_t m_base_address;
	uintptr_t m_player_ptr;
	Player m_player;
	Lexer m_lex;
	VMTHook* m_hook;

	std::string most_recent;

	uintptr_t active_lua_state;
	bool lua_loaded = false;
	bool is_moonkin_transparent = false;
	int m_last_morphed_id = 0;
};

} // namespace morph
