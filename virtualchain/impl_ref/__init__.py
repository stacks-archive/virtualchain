# required callbacks
from reference import get_virtual_chain_name, get_virtual_chain_version, get_first_block_id, get_db_state, db_parse, db_check, db_commit, db_save, db_serialize

# optional
try:
   from reference import get_op_processing_order
except:
   def get_op_processing_order():
      return None