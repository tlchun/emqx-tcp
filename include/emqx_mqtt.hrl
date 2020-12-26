%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:27
%%%-------------------------------------------------------------------
-author("root").

-record(mqtt_packet_header, {type = 0, dup = false, qos = 0, retain = false}).

-record(mqtt_packet_connect,
{proto_name = <<"MQTT">>, proto_ver = 4,
  is_bridge = false, clean_start = true,
  will_flag = false, will_qos = 0, will_retain = false,
  keepalive = 0, properties = #{}, clientid = <<>>,
  will_props = #{}, will_topic = undefined,
  will_payload = undefined, username = undefined,
  password = undefined}).

-record(mqtt_packet_connack,
{ack_flags, reason_code, properties = #{}}).

-record(mqtt_packet_publish,
{topic_name, packet_id, properties = #{}}).

-record(mqtt_packet_puback,
{packet_id, reason_code, properties = #{}}).

-record(mqtt_packet_subscribe,
{packet_id, properties = #{}, topic_filters}).

-record(mqtt_packet_suback,
{packet_id, properties = #{}, reason_codes}).

-record(mqtt_packet_unsubscribe,
{packet_id, properties = #{}, topic_filters}).

-record(mqtt_packet_unsuback,
{packet_id, properties = #{}, reason_codes}).

-record(mqtt_packet_disconnect,
{reason_code, properties = #{}}).

-record(mqtt_packet_auth,
{reason_code, properties = #{}}).

-record(mqtt_packet,
{header  :: #mqtt_packet_header{},
  variable  ::
  #mqtt_packet_connect{} | #mqtt_packet_connack{} |
  #mqtt_packet_publish{} | #mqtt_packet_puback{} |
  #mqtt_packet_subscribe{} | #mqtt_packet_suback{} |
  #mqtt_packet_unsubscribe{} | #mqtt_packet_unsuback{} |
  #mqtt_packet_disconnect{} | #mqtt_packet_auth{} |
  pos_integer() | undefined,
  payload  :: binary() | undefined}).

-record(mqtt_msg,
{qos = 0, retain = false, dup = false, packet_id, topic,
  props, payload}).
