import datetime
import psutil


class PyTorchLogCallback:
    """PyTorch-compatible version of LogCallback"""

    def __init__(self):
        pass

    @staticmethod
    def get_memory_info():
        process = psutil.Process()
        memory_info = process.memory_info()
        return str(memory_info)

    def on_epoch_end(self, epoch, logs=None):
        print(str(datetime.datetime.now()), flush=True)
        print(f"{epoch + 1}:{self.get_memory_info()}", flush=True)
        if logs:
            print(logs, flush=True)


# Alias for backward compatibility
LogCallback = PyTorchLogCallback
