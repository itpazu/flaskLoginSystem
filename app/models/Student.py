from .base_class import BaseClass


class Student(BaseClass):

    def __init__(self, student_obj):
        lower_case_obj = ((k.lower(), v) for k, v in student_obj.items())

        new_obj = {}
        for k, v in lower_case_obj:
            new_obj[k] = v

        self.first_name = new_obj['first_name']
        self.last_name = new_obj['last_name']
        self.email = new_obj['email']
        self.created_at = self.updated_at()
        self.last_update = self.updated_at()
        self.existing_skills = new_obj['existing_skills'] or [] ## [{skill: level}]
        self.interested_courses = new_obj['interested_courses'] or [ ]##[skill]



