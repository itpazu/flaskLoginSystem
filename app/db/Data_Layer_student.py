from .Data_Layer import DataLayer
from app.models.Student import Student
from bson import ObjectId
from pymongo import ReturnDocument

class DataLayerStudent(DataLayer):
    def __init__(self):
        super().__init__()
        self.db = self.get_db()
        self.student_collection = self.db.Students


    def add_student(self, content, conf=None):
        try:
            email = content['email']
            new_user = Student(content)
            print(content)
            insert_new = self.student_collection.update({"email": email},
                                                {"$setOnInsert": (new_user.__dict__)}, upsert=True)
            if 'upserted' in insert_new:
                return self.get_doc_by_user_id('Students', insert_new['upserted'])
            else:
                raise Exception({'message': 'Student already exists!', 'status_code': 400})

        except Exception as error:
            raise error


    def edit_capability(self, request):
        try:
            student_id = request.args.get('id')
            skill = request.args.get('skill')
            new_level = request.args.get('level')
            if student_id is None or skill is None or new_level is None:
                raise Exception({"message": 'skill update failed', "log": "data is missing in the request"})
            # find_only = self.student_collection.find_one({"_id": ObjectId(student_id), "existing_skills.{}".format(skill) :{'$exists': True}})
            # print(find_only)
            modify_skill = self.student_collection.find_one_and_update(
                {"_id": ObjectId(student_id), "existing_skills.{}".format(skill):{'$exists': True}},
                {
                    "$set": {"existing_skills.$.{}".format(skill): new_level, "last_update":
                        Student.updated_at(), "last_change": "set skill %s to level %s" % (skill, new_level)},

                },
                return_document=ReturnDocument.AFTER)
            if modify_skill is None:
                raise Exception({"message": 'skill update failed'})
            return modify_skill
        except Exception as error:
            raise error

    def add_capability(self, request):
        try:
            skill_to_update = request.args.get('update')
            student_id = request.args.get('id')
            skill = request.args.get('skill')
            new_level = request.args.get('level')
            if skill_to_update == 'true':
                print('inside if')
                student_modified = self.student_collection.find_one_and_update(
                {'_id': ObjectId(student_id), "existing_skills.{}".format(skill)
                                                                            :{'$exists': False}},
                {
                    "$addToSet": {"existing_skills": {skill: new_level}},
                    "$set": {"last_update": Student.updated_at(), "last_change": "add new skill %s" % skill},
                    "$pull": {"interested_courses": skill}

                },
                    return_document=ReturnDocument.AFTER)
            else:
                student_modified = self.student_collection.find_one_and_update(
                    {'_id': ObjectId(student_id)},
                    {
                        "$addToSet": {"interested_courses": skill},
                        "$set": {"last_update": Student.updated_at(), "last_change": "add new desired skill %s" % skill}

                    },
                    return_document=ReturnDocument.AFTER)
            if student_modified:
                return student_modified
            else:
                raise Exception("database query returned None")
        except Exception as error:
            raise Exception({"message": f'update failed: {error}'})

    def delete_student(self, request):
        try:
            _id = request.json['user_id']
            skill = request.json['skill']
            deleted = self.student_collection.find_one_and_update({"_id": ObjectId(_id)},
                {
                    "$pull": {"existing_skills": { skill: {'$exists': True}} },
                    "$set": {"last_update": Student.updated_at(), "last_change": "delete %s" % (skill)},

                },
                return_document=ReturnDocument.AFTER)
            if deleted:

                return deleted
            else:
                raise Exception('db update failed')

        except Exception as error:
            raise Exception({"message": "delete failed", "log": error, "status_code": 400})