package com.example.courseworkLuchnetskyi.model;

import jakarta.persistence.*;
import lombok.*;
import java.util.List;
import com.example.courseworkLuchnetskyi.model.Player;

@Entity
@Table(name = "teams")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Team {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String city;

    @OneToMany(mappedBy = "team", cascade = CascadeType.ALL)
    private List<Player> players;
}
