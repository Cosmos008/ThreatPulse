def route_event(event):

    event_type = event.get("event_type")

    if event_type in ["login_attempt", "login_success", "password_reset"]:
        return "auth_events"

    if event_type == "music_play":
        return "stream_events"

    if event_type in ["session_start", "session_end"]:
        return "session_events"

    return None