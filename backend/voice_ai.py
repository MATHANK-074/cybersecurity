import speech_recognition as sr

def verify_voice_phrase(audio_path, expected_phrase):
    """
    AI Detection: Uses Google Speech Recognition to verify if 
    the spoken audio matches the dynamic challenge phrase.
    """
    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(audio_path) as source:
            audio_data = recognizer.record(source)
            # AI Level 1: Speech-to-Text conversion
            actual_text = recognizer.recognize_google(audio_data)
            
            # AI Level 2: Pattern Matching
            if actual_text.lower() == expected_phrase.lower():
                return True, actual_text
            return False, actual_text
    except Exception as e:
        return False, str(e)