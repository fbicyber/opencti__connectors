from process_file import FileProcessor


processor = FileProcessor()
recs = processor.get_recs(file_name="/Users/mmasters/Desktop/threatActors.csv")
validated_recs = processor.validate_recs(recs)
