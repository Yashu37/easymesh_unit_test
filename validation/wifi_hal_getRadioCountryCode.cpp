/*
 * HANDLER: wifi_hal_getRadioCountryCode
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:495-511
 * (~/Desktop/G/rdk-wifi-hal), with the helpers copied verbatim next to it from src/wifi_hal_nl80211_utils.c
 * (declared static here only so the harnesses link together): get_radio_by_rdk_index (2271-2283),
 * get_coutry_str_from_code (3136-3154) and the country table wifi_country_map (1011-1260, 247 entries).
 * With RDK_GCT_FIX 0 everything is the VERBATIM original (reproduces the findings); with RDK_GCT_FIX 1 the
 * function carries FIX 1 and the table FIX 2 and 3 below (the table is the source of the wrong strings, so the
 * fix is applied to the harness copy of the table; the findings name the helper's file/line).
 *
 * Scaffolding only: g_wifi_hal / the radio hold just num_radios, radio_info[], rdk_radio_index and the REAL
 * wifi_radio_operationParam_t (wifi_hal.h); struct wifiCountryEnumStrMap is the one of wifi_hal_priv.h:319.  The
 * function under test is renamed hwr_wifi_hal_getRadioCountryCode.
 */
#include "hwr_gct.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* 1 = with FIX 1..3, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_GCT_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_radio_info_t     hwr_gct_radio_t
#define g_wifi_hal            hwr_gct_world
#define wifi_hal_getRadioCountryCode hwr_wifi_hal_getRadioCountryCode
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

struct wifiCountryEnumStrMap {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
};

hwr_gct_world_t hwr_gct_world;

/* --- copied from wifi_hal_nl80211_utils.c:1011 --- */
static struct wifiCountryEnumStrMap wifi_country_map[] =
{
    {wifi_countrycode_AC,"AC"}, /**< ASCENSION ISLAND */
    {wifi_countrycode_AD,"AD"}, /**< ANDORRA */
    {wifi_countrycode_AE,"AE"}, /**< UNITED ARAB EMIRATES */
    {wifi_countrycode_AF,"AF"}, /**< AFGHANISTAN */
    {wifi_countrycode_AG,"AG"}, /**< ANTIGUA AND BARBUDA */
    {wifi_countrycode_AI,"AI"}, /**< ANGUILLA */
    {wifi_countrycode_AL,"AL"}, /**< ALBANIA */
    {wifi_countrycode_AM,"AM"}, /**< ARMENIA */
    {wifi_countrycode_AN,"AN"}, /**< NETHERLANDS ANTILLES */
    {wifi_countrycode_AO,"AO"}, /**< ANGOLA */
    {wifi_countrycode_AQ,"AQ"}, /**< ANTARCTICA */
    {wifi_countrycode_AR,"AR"}, /**< ARGENTINA */
    {wifi_countrycode_AS,"AS"}, /**< AMERICAN SAMOA */
    {wifi_countrycode_AT,"AT"}, /**< AUSTRIA */
    {wifi_countrycode_AU,"AU"}, /**< AUSTRALIA */
    {wifi_countrycode_AW,"AW"}, /**< ARUBA */
    {wifi_countrycode_AZ,"AZ"}, /**< AZERBAIJAN */
    {wifi_countrycode_BA,"BA"}, /**< BOSNIA AND HERZEGOVINA */
    {wifi_countrycode_BB,"BB"}, /**< BARBADOS */
    {wifi_countrycode_BD,"BD"}, /**< BANGLADESH */
    {wifi_countrycode_BE,"BE"}, /**< BELGIUM */
    {wifi_countrycode_BF,"BF"}, /**< BURKINA FASO */
    {wifi_countrycode_BG,"BG"}, /**< BULGARIA */
    {wifi_countrycode_BH,"BH"}, /**< BAHRAIN */
    {wifi_countrycode_BI,"BI"}, /**< BURUNDI */
    {wifi_countrycode_BJ,"BJ"}, /**< BENIN */
    {wifi_countrycode_BM,"BM"}, /**< BERMUDA */
    {wifi_countrycode_BN,"BN"}, /**< BRUNEI DARUSSALAM */
    {wifi_countrycode_BO,"BO"}, /**< BOLIVIA */
    {wifi_countrycode_BR,"BR"}, /**< BRAZIL */
    {wifi_countrycode_BS,"BS"}, /**< BAHAMAS */
    {wifi_countrycode_BT,"BT"}, /**< BHUTAN */
    {wifi_countrycode_BV,"BV"}, /**< BOUVET ISLAND */
    {wifi_countrycode_BW,"BW"}, /**< BOTSWANA */
    {wifi_countrycode_BY,"BY"}, /**< BELARUS */
    {wifi_countrycode_BZ,"BZ"}, /**< BELIZE */
    {wifi_countrycode_CA,"CA"}, /**< CANADA */
    {wifi_countrycode_CC,"CC"}, /**< COCOS (KEELING) ISLANDS */
    {wifi_countrycode_CD,"CD"}, /**< CONGO,THE DEMOCRATIC REPUBLIC OF THE */
    {wifi_countrycode_CF,"CF"}, /**< CENTRAL AFRICAN REPUBLIC */
    {wifi_countrycode_CG,"CG"}, /**< CONGO */
    {wifi_countrycode_CH,"CH"}, /**< SWITZERLAND */
    {wifi_countrycode_CI,"CI"}, /**< COTE D'IVOIRE */
    {wifi_countrycode_CK,"CK"}, /**< COOK ISLANDS */
    {wifi_countrycode_CL,"CL"}, /**< CHILE */
    {wifi_countrycode_CM,"CM"}, /**< CAMEROON */
    {wifi_countrycode_CN,"CN"}, /**< CHINA */
    {wifi_countrycode_CO,"CO"}, /**< COLOMBIA */
    {wifi_countrycode_CP,"CP"}, /**< CLIPPERTON ISLAND */
    {wifi_countrycode_CR,"CR"}, /**< COSTA RICA */
    {wifi_countrycode_CU,"CU"}, /**< CUBA */
    {wifi_countrycode_CV,"CV"}, /**< CAPE VERDE */
    {wifi_countrycode_CY,"CY"}, /**< CYPRUS */
    {wifi_countrycode_CX,"CX"}, /**< CHRISTMAS ISLAND */
    {wifi_countrycode_CZ,"CZ"}, /**< CZECH REPUBLIC */
    {wifi_countrycode_DE,"DE"}, /**< GERMANY */
    {wifi_countrycode_DJ,"DJ"}, /**< DJIBOUTI */
    {wifi_countrycode_DK,"DK"}, /**< DENMARK */
    {wifi_countrycode_DM,"DM"}, /**< DOMINICA */
    {wifi_countrycode_DO,"DO"}, /**< DOMINICAN REPUBLIC */
    {wifi_countrycode_DZ,"DZ"}, /**< ALGERIA */
    {wifi_countrycode_EC,"EC"}, /**< ECUADOR */
    {wifi_countrycode_EE,"EE"}, /**< ESTONIA */
    {wifi_countrycode_EG,"EG"}, /**< EGYPT */
    {wifi_countrycode_EH,"EH"}, /**< WESTERN SAHARA */
    {wifi_countrycode_ER,"ER"}, /**< ERITREA */
    {wifi_countrycode_ES,"ES"}, /**< SPAIN */
    {wifi_countrycode_ET,"ET"}, /**< ETHIOPIA */
    {wifi_countrycode_FI,"FI"}, /**< FINLAND */
    {wifi_countrycode_FJ,"FJ"}, /**< FIJI */
    {wifi_countrycode_FK,"FK"}, /**< FALKLAND ISLANDS (MALVINAS) */
    {wifi_countrycode_FM,"FM"}, /**< MICRONESIA FEDERATED STATES OF */
    {wifi_countrycode_FO,"FO"}, /**< FAROE ISLANDS */
    {wifi_countrycode_FR,"FR"}, /**< FRANCE */
    {wifi_countrycode_GA,"GA"}, /**< GABON */
    {wifi_countrycode_GB,"GB"}, /**< UNITED KINGDOM */
    {wifi_countrycode_GD,"GD"}, /**< GRENADA */
    {wifi_countrycode_GE,"GE"}, /**< GEORGIA */
    {wifi_countrycode_GF,"GF"}, /**< FRENCH GUIANA */
    {wifi_countrycode_GG,"GG"}, /**< GUERNSEY */
    {wifi_countrycode_GH,"GH"}, /**< GHANA */
    {wifi_countrycode_GI,"GI"}, /**< GIBRALTAR */
    {wifi_countrycode_GL,"GL"}, /**< GREENLAND */
    {wifi_countrycode_GM,"GM"}, /**< GAMBIA */
    {wifi_countrycode_GN,"GN"}, /**< GUINEA */
    {wifi_countrycode_GP,"GP"}, /**< GUADELOUPE */
    {wifi_countrycode_GQ,"GQ"}, /**< EQUATORIAL GUINEA */
    {wifi_countrycode_GR,"GR"}, /**< GREECE */
    {wifi_countrycode_GS,"GS"}, /**< SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS */
    {wifi_countrycode_GT,"GT"}, /**< GUATEMALA */
    {wifi_countrycode_GU,"GU"}, /**< GUAM */
    {wifi_countrycode_GW,"GW"}, /**< GUINEA-BISSAU */
    {wifi_countrycode_GY,"GY"}, /**< GUYANA */
    {wifi_countrycode_HR,"HR"}, /**< CROATIA */
    {wifi_countrycode_HT,"HT"}, /**< HAITI */
    {wifi_countrycode_HM,"HM"}, /**< HEARD ISLAND AND MCDONALD ISLANDS */
    {wifi_countrycode_HN,"HN"}, /**< HONDURAS */
    {wifi_countrycode_HK,"HK"}, /**< HONG KONG */
    {wifi_countrycode_HU,"HU"}, /**< HUNGARY */
    {wifi_countrycode_IS,"IS"}, /**< ICELAND */
    {wifi_countrycode_IN,"IN"}, /**< INDIA */
    {wifi_countrycode_ID,"ID"}, /**< INDONESIA */
    {wifi_countrycode_IR,"IR"}, /**< IRAN, ISLAMIC REPUBLIC OF */
    {wifi_countrycode_IQ,"IQ"}, /**< IRAQ */
    {wifi_countrycode_IE,"IE"}, /**< IRELAND */
    {wifi_countrycode_IL,"IL"}, /**< ISRAEL */
    {wifi_countrycode_IM,"IM"}, /**< MAN, ISLE OF */
    {wifi_countrycode_IT,"IT"}, /**< ITALY */
    {wifi_countrycode_IO,"IO"}, /**< BRITISH INDIAN OCEAN TERRITORY */
    {wifi_countrycode_JM,"JM"}, /**< JAMAICA */
    {wifi_countrycode_JP,"JP"}, /**< JAPAN */
    {wifi_countrycode_JE,"JE"}, /**< JERSEY */
#if RDK_GCT_FIX
    {wifi_countrycode_JO,"JO"}, /**< JORDAN (FIX 2: was the lower case "jo") */
#else
    {wifi_countrycode_JO,"jo"}, /**< JORDAN */
#endif
    {wifi_countrycode_KE,"KE"}, /**< KENYA */
    {wifi_countrycode_KG,"KG"}, /**< KYRGYZSTAN */
    {wifi_countrycode_KH,"KH"}, /**< CAMBODIA */
    {wifi_countrycode_KI,"KI"}, /**< KIRIBATI */
    {wifi_countrycode_KM,"KM"}, /**< COMOROS */
    {wifi_countrycode_KN,"KN"}, /**< SAINT KITTS AND NEVIS */
    {wifi_countrycode_KP,"KP"}, /**< KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF */
    {wifi_countrycode_KR,"KR"}, /**< KOREA, REPUBLIC OF */
    {wifi_countrycode_KW,"KW"}, /**< KUWAIT */
    {wifi_countrycode_KY,"KY"}, /**< CAYMAN ISLANDS */
    {wifi_countrycode_KZ,"KZ"}, /**< KAZAKHSTAN */
    {wifi_countrycode_LA,"LA"}, /**< LAO PEOPLE'S DEMOCRATIC REPUBLIC */
    {wifi_countrycode_LB,"LB"}, /**< LEBANON */
    {wifi_countrycode_LC,"LC"}, /**< SAINT LUCIA */
    {wifi_countrycode_LI,"LI"}, /**< LIECHTENSTEIN */
    {wifi_countrycode_LK,"LK"}, /**< SRI LANKA */
    {wifi_countrycode_LR,"LR"}, /**< LIBERIA */
    {wifi_countrycode_LS,"LS"}, /**< LESOTHO */
    {wifi_countrycode_LT,"LT"}, /**< LITHUANIA */
    {wifi_countrycode_LU,"LU"}, /**< LUXEMBOURG */
    {wifi_countrycode_LV,"LV"}, /**< LATVIA */
    {wifi_countrycode_LY,"LY"}, /**< LIBYAN ARAB JAMAHIRIYA */
    {wifi_countrycode_MA,"MA"}, /**< MOROCCO */
    {wifi_countrycode_MC,"MC"}, /**< MONACO */
    {wifi_countrycode_MD,"MD"}, /**< MOLDOVA, REPUBLIC OF */
    {wifi_countrycode_ME,"ME"}, /**< MONTENEGRO */
    {wifi_countrycode_MG,"MG"}, /**< MADAGASCAR */
    {wifi_countrycode_MH,"MH"}, /**< MARSHALL ISLANDS */
    {wifi_countrycode_MK,"MK"}, /**< MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF */
    {wifi_countrycode_ML,"ML"}, /**< MALI */
    {wifi_countrycode_MM,"MM"}, /**< MYANMAR */
    {wifi_countrycode_MN,"MN"}, /**< MONGOLIA */
    {wifi_countrycode_MO,"MO"}, /**< MACAO */
    {wifi_countrycode_MQ,"MQ"}, /**< MARTINIQUE */
    {wifi_countrycode_MR,"MR"}, /**< MAURITANIA */
    {wifi_countrycode_MS,"MS"}, /**< MONTSERRAT */
    {wifi_countrycode_MT,"MT"}, /**< MALTA */
    {wifi_countrycode_MU,"MU"}, /**< MAURITIUS */
    {wifi_countrycode_MV,"MV"}, /**< MALDIVES */
    {wifi_countrycode_MW,"MW"}, /**< MALAWI */
    {wifi_countrycode_MX,"MX"}, /**< MEXICO */
    {wifi_countrycode_MY,"MY"}, /**< MALAYSIA */
    {wifi_countrycode_MZ,"MZ"}, /**< MOZAMBIQUE */
    {wifi_countrycode_NA,"NA"}, /**< NAMIBIA */
    {wifi_countrycode_NC,"NC"}, /**< NEW CALEDONIA */
    {wifi_countrycode_NE,"NE"}, /**< NIGER */
    {wifi_countrycode_NF,"NF"}, /**< NORFOLK ISLAND */
    {wifi_countrycode_NG,"NG"}, /**< NIGERIA */
    {wifi_countrycode_NI,"NI"}, /**< NICARAGUA */
    {wifi_countrycode_NL,"NL"}, /**< NETHERLANDS */
    {wifi_countrycode_NO,"NO"}, /**< NORWAY */
    {wifi_countrycode_NP,"NP"}, /**< NEPAL */
    {wifi_countrycode_NR,"NR"}, /**< NAURU */
    {wifi_countrycode_NU,"NU"}, /**< NIUE */
    {wifi_countrycode_NZ,"NZ"}, /**< NEW ZEALAND */
    {wifi_countrycode_MP,"MP"}, /**< NORTHERN MARIANA ISLANDS */
    {wifi_countrycode_OM,"OM"}, /**< OMAN */
    {wifi_countrycode_PA,"PA"}, /**< PANAMA */
    {wifi_countrycode_PE,"PE"}, /**< PERU */
    {wifi_countrycode_PF,"PF"}, /**< FRENCH POLYNESIA */
    {wifi_countrycode_PG,"PG"}, /**< PAPUA NEW GUINEA */
    {wifi_countrycode_PH,"PH"}, /**< PHILIPPINES */
    {wifi_countrycode_PK,"PK"}, /**< PAKISTAN */
    {wifi_countrycode_PL,"PL"}, /**< POLAND */
    {wifi_countrycode_PM,"PM"}, /**< SAINT PIERRE AND MIQUELON */
    {wifi_countrycode_PN,"PN"}, /**< PITCAIRN */
    {wifi_countrycode_PR,"PR"}, /**< PUERTO RICO */
    {wifi_countrycode_PS,"PS"}, /**< PALESTINIAN TERRITORY,OCCUPIED */
    {wifi_countrycode_PT,"PT"}, /**< PORTUGAL */
    {wifi_countrycode_PW,"PW"}, /**< PALAU */
    {wifi_countrycode_PY,"PY"}, /**< PARAGUAY */
    {wifi_countrycode_QA,"QA"}, /**< QATAR */
    {wifi_countrycode_RE,"RE"}, /**< REUNION */
    {wifi_countrycode_RO,"RO"}, /**< ROMANIA */
    {wifi_countrycode_RS,"RS"}, /**< SERBIA */
    {wifi_countrycode_RU,"RU"}, /**< RUSSIAN FEDERATION */
    {wifi_countrycode_RW,"RW"}, /**< RWANDA */
    {wifi_countrycode_SA,"SA"}, /**< SAUDI ARABIA */
    {wifi_countrycode_SB,"SB"}, /**< SOLOMON ISLANDS */
    {wifi_countrycode_SD,"SD"}, /**< SUDAN */
    {wifi_countrycode_SE,"SE"}, /**< SWEDEN */
    {wifi_countrycode_SC,"SC"}, /**< SEYCHELLES */
    {wifi_countrycode_SG,"SG"}, /**< SINGAPORE */
    {wifi_countrycode_SH,"SH"}, /**< SAINT HELENA */
    {wifi_countrycode_SI,"SI"}, /**< SLOVENIA */
    {wifi_countrycode_SJ,"SJ"}, /**< SVALBARD AND JAN MAYEN */
    {wifi_countrycode_SK,"SK"}, /**< SLOVAKIA */
    {wifi_countrycode_SL,"SL"}, /**< SIERRA LEONE */
    {wifi_countrycode_SM,"SM"}, /**< SAN MARINO */
    {wifi_countrycode_SN,"SN"}, /**< SENEGAL */
    {wifi_countrycode_SO,"SO"}, /**< SOMALIA */
    {wifi_countrycode_SR,"SR"}, /**< SURINAME */
    {wifi_countrycode_ST,"ST"}, /**< SAO TOME AND PRINCIPE */
    {wifi_countrycode_SV,"SV"}, /**< EL SALVADOR */
    {wifi_countrycode_SY,"SY"}, /**< SYRIAN ARAB REPUBLIC */
    {wifi_countrycode_SZ,"SZ"}, /**< SWAZILAND */
    {wifi_countrycode_TA,"TA"}, /**< TRISTAN DA CUNHA */
    {wifi_countrycode_TC,"TC"}, /**< TURKS AND CAICOS ISLANDS */
    {wifi_countrycode_TD,"TD"}, /**< CHAD */
    {wifi_countrycode_TF,"TF"}, /**< FRENCH SOUTHERN TERRITORIES */
    {wifi_countrycode_TG,"TG"}, /**< TOGO */
    {wifi_countrycode_TH,"TH"}, /**< THAILAND */
    {wifi_countrycode_TJ,"TJ"}, /**< TAJIKISTAN */
    {wifi_countrycode_TK,"TK"}, /**< TOKELAU */
    {wifi_countrycode_TL,"TL"}, /**< TIMOR-LESTE (EAST TIMOR) */
    {wifi_countrycode_TM,"TM"}, /**< TURKMENISTAN */
    {wifi_countrycode_TN,"TN"}, /**< TUNISIA */
    {wifi_countrycode_TO,"TO"}, /**< TONGA */
    {wifi_countrycode_TR,"TR"}, /**< TURKEY */
    {wifi_countrycode_TT,"TT"}, /**< TRINIDAD AND TOBAGO */
    {wifi_countrycode_TV,"TV"}, /**< TUVALU */
    {wifi_countrycode_TW,"TW"}, /**< TAIWAN, PROVINCE OF CHINA */
    {wifi_countrycode_TZ,"TZ"}, /**< TANZANIA, UNITED REPUBLIC OF */
    {wifi_countrycode_UA,"UA"}, /**< UKRAINE */
    {wifi_countrycode_UG,"UG"}, /**< UGANDA */
    {wifi_countrycode_UM,"UM"}, /**< UNITED STATES MINOR OUTLYING ISLANDS */
    {wifi_countrycode_US,"US"}, /**< UNITED STATES */
    {wifi_countrycode_UY,"UY"}, /**< URUGUAY */
    {wifi_countrycode_UZ,"UZ"}, /**< UZBEKISTAN */
    {wifi_countrycode_VA,"VA"}, /**< HOLY SEE (VATICAN CITY STATE) */
    {wifi_countrycode_VC,"VC"}, /**< SAINT VINCENT AND THE GRENADINES */
    {wifi_countrycode_VE,"VE"}, /**< VENEZUELA */
    {wifi_countrycode_VG,"VG"}, /**< VIRGIN ISLANDS, BRITISH */
    {wifi_countrycode_VI,"VI"}, /**< VIRGIN ISLANDS, U.S. */
    {wifi_countrycode_VN,"VN"}, /**< VIET NAM */
    {wifi_countrycode_VU,"VU"}, /**< VANUATU */
    {wifi_countrycode_WF,"WF"}, /**< WALLIS AND FUTUNA */
    {wifi_countrycode_WS,"WS"}, /**< SAMOA */
    {wifi_countrycode_YE,"YE"}, /**< YEMEN */
    {wifi_countrycode_YT,"YT"}, /**< MAYOTTE */
    {wifi_countrycode_YU,"YU"}, /**< YUGOSLAVIA */
    {wifi_countrycode_ZA,"ZA"}, /**< SOUTH AFRICA */
    {wifi_countrycode_ZM,"ZM"}, /**< ZAMBIA */
    {wifi_countrycode_ZW,"ZW"} /**< ZIMBABWE */
#if RDK_GCT_FIX
    , /* the last original entry has no trailing comma */
    /* FIX 3: valid country codes of wifi_countrycode_type_t that were missing from the table (they were reported as the default "US") */
    {wifi_countrycode_AX,"AX"}, /**< ALAND ISLANDS */
    {wifi_countrycode_BL,"BL"}, /**< SAINT BARTHELEMY */
    {wifi_countrycode_CW,"CW"}, /**< CURACAO */
    {wifi_countrycode_MF,"MF"}, /**< SAINT MARTIN */
    {wifi_countrycode_SX,"SX"}, /**< SINT MAARTEN */
    {wifi_countrycode_BQ,"BQ"}, /**< BONAIRE, SINT EUSTATIUS AND SABA */
    {wifi_countrycode_00,"00"}, /**< WORLD REGULATORY DOMAIN */
#endif
};

/* --- copied from wifi_hal_nl80211_utils.c:3136 --- */
static INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    unsigned int index = 0;
    bool value_updated = false;

    for (index = 0; index < ARRAY_SZ(wifi_country_map); index++) {
        if (wifi_country_map[index].countryCode == code) {
            strcpy(country, wifi_country_map[index].countryStr);
            value_updated = true;
            break;
        }
    }

    if (value_updated == false) {
        //Copy default value
        strcpy(country, "US");
    }
    return RETURN_OK;
}

/* --- copied from wifi_hal_nl80211_utils.c:2271 --- */
static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}

/* --- copied from hal_ipc_wifi_wrappers.c:495 --- */
extern "C" {
INT wifi_hal_getRadioCountryCode(   INT radioIndex,
                                    CHAR *output_string)
{
    wifi_radio_info_t *radio;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
#if RDK_GCT_FIX
    /* FIX 1: output_string is written unchecked (strcpy() in get_coutry_str_from_code). */
    if (output_string == NULL) {
        return -1;
    }
#endif
    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
        wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
        return -1;
    }

    get_coutry_str_from_code(radio->oper_param.countryCode, output_string);

    return 0;
}
}
