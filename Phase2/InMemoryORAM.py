import random
import numpy as np

class InMemoryORAM:
    def __init__(self, ads_embeddings):
        """
        Initialize in-memory storage for ad embeddings with shuffling to mimic ORAM.
        """
        self.storage = list(ads_embeddings.items())  # Store ads
        self.index_map = list(range(len(self.storage)))  # Map of original indices to current positions
        self.access_history = []  # Track accessed indices for debugging (optional)

    def access(self, index):
        """
        Access an ad at a specific index and shuffle storage to mimic ORAM.
        """
        if index < 0 or index >= len(self.index_map):
            raise IndexError("Invalid access index for ORAM storage.")
        
        # Get the current position of the original index
        current_position = self.index_map.index(index)
        
        # Retrieve the ad embedding
        ad = self.storage[current_position]
        
        # Record access for debugging
        self.access_history.append(index)

        # Shuffle the storage after access to hide patterns
        combined = list(zip(self.storage, self.index_map))
        random.shuffle(combined)
        self.storage, self.index_map = zip(*combined)
        print(ad)
        return ad

    def size(self):
        """
        Return the number of items in storage.
        """
        return len(self.storage)
