from typing import Dict, Any, List
import logging

class AlgorithmsRegister:
    def __init__(self):
        self.algorithms = {}

    def register_algorithm(self, algorithm_name: str, algorithm_class: Any, algorithm_parameters: Dict[str, Any] = {}):
        logging.info(f"Registering algorithm: {algorithm_name}")
        self.algorithms[algorithm_name] = {'class':algorithm_class, 'algorithm_parameters':algorithm_parameters}

    def get_algorithm(self, algorithm_name: str) -> Dict[str, Any]:
        return self.algorithms.get(algorithm_name)

    def get_algorithm_names(self) -> List[str]:
        return list(self.algorithms.keys())


