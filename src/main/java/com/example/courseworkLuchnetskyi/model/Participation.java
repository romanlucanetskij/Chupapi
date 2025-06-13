package com.example.courseworkLuchnetskyi.model;

import jakarta.persistence.*;
import lombok.*;
import com.example.courseworkLuchnetskyi.model.Team;
import com.example.courseworkLuchnetskyi.model.Tournament;

@Entity
@Table(name = "participations")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Participation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Team team;

    @ManyToOne
    private Tournament tournament;

    @ManyToOne
    private Player player;

    private int goals;
}
